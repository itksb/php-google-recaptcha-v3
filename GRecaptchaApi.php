<?php
declare(strict_types=1);


/**
 * Interface GRecaptchaErrorInterface
 */
interface GRecaptchaErrorInterface
{
    /**
     * Returns true if there were errors during request
     * @return bool
     */
    public function hasErrors(): bool;

    /**
     * Returns array of error messages
     * @return string[]
     */
    public function getErrors(): array;

    /**
     * Add error to the container
     * @param string $error
     * @return mixed
     */
    public function addError(string $error): void;
}

/**
 * Interface GRecaptchaHttpClientInterface
 */
interface GRecaptchaHttpClientInterface
{
    /**
     * Sends http request to Google recaptcha server
     * @param string $secret
     * @param string $response
     * @param string $remoteip
     * @return GRecaptchaResponse
     */
    public function sendRequest(string $secret, string $response, string $remoteip = ''): GRecaptchaResponse;
}

/**
 * Class GRecaptchaResponse
 * @author Sergey ksb@itksb.com
 */
final class GRecaptchaResponse implements GRecaptchaErrorInterface
{
    /** @var bool $success */
    private $success;
    /** @var float $score */
    private $score;
    /** @var string $hostname */
    private $hostname;
    /** @var string $action */
    private $action;

    /** @var string[] */
    private $errors = [];

    /**
     * Fill properties
     * @param bool $success
     * @param float $score
     * @param string $hostname
     * @param string $action
     * @return GRecaptchaResponse
     */
    public function fill(
        bool $success,
        float $score,
        string $hostname,
        string $action
    ): GRecaptchaResponse
    {
        $this->success = $success;
        $this->score = $score;
        $this->hostname = $hostname;
        $this->action = $action;
        return $this;
    }

    /**
     * @inheritDoc
     */
    public function hasErrors(): bool
    {
        return count($this->errors) > 0;
    }

    /**
     * @inheritDoc
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * @inheritDoc
     */
    public function addError(string $error): void
    {
        if (mb_strlen($error)) {
            $this->errors[] = $error;
        }
    }

    /**
     * @return bool
     */
    public function isSuccess(): bool
    {
        return $this->success;
    }

    /**
     * @param bool $success
     */
    public function setSuccess(bool $success): void
    {
        $this->success = $success;
    }

    /**
     * @return float
     */
    public function getScore(): float
    {
        return $this->score;
    }

    /**
     * @param float $score
     */
    public function setScore(float $score): void
    {
        $this->score = $score;
    }

    /**
     * @return string
     */
    public function getHostname(): string
    {
        return $this->hostname;
    }

    /**
     * @param string $hostname
     */
    public function setHostname(string $hostname): void
    {
        $this->hostname = $hostname;
    }

    /**
     * @return string
     */
    public function getAction(): string
    {
        return $this->action;
    }

    /**
     * @param string $action
     */
    public function setAction(string $action): void
    {
        $this->action = $action;
    }

}

/**
 * Class GRecaptchaCurlHttpClient
 * @author Sergey ksb@itksb.com
 */
class GRecaptchaCurlHttpClient implements GRecaptchaHttpClientInterface
{
    const MISSING_INPUT_SECRET = 'missing-input-secret';
    const INVALID_INPUT_SECRET = 'invalid-input-secret';
    const MISSING_INPUT_RESPONSE = 'missing-input-response';
    const INVALID_INPUT_RESPONSE = 'invalid-input-response';
    const BAD_REQUEST = 'bad-request';
    const TIMEOUT_OR_DUPLICATE = 'timeout-or-duplicate';

    /**
     * Send validation request
     * @param string $secret
     * @param string $response
     * @param string $remoteip
     * @return GRecaptchaResponse
     * @throws GRecaptchaGoogleResponseValidationException
     */
    public function sendRequest(string $secret, string $response, string $remoteip = ''): GRecaptchaResponse
    {
        $returnResponse = new GRecaptchaResponse();
        /** @var bool $isValidInput */
        $isValidInput = mb_strlen($secret) && mb_strlen($response);
        if (!$isValidInput) {
            throw new InvalidArgumentException('One or more of required gRecaptcha arguments is empty.');
        }

        $validationRequestParams = ['secret' => $secret, 'response' => $response,];
        !empty($remoteip) && ($validationRequestParams['remoteip'] = $remoteip);

        $httpClient = curl_init();
        curl_setopt($httpClient, CURLOPT_URL, "https://www.google.com/recaptcha/api/siteverify");
        curl_setopt($httpClient, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded;']);
        curl_setopt($httpClient, CURLOPT_TIMEOUT, 10);
        curl_setopt($httpClient, CURLOPT_POST, true);
        curl_setopt($httpClient, CURLOPT_POSTFIELDS, http_build_query($validationRequestParams));
        curl_setopt($httpClient, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($httpClient, CURLOPT_RETURNTRANSFER, true);
        /** @var string|bool $rawGoogleResponse the result on success, false on failure. */
        $rawGoogleResponse = curl_exec($httpClient);
        if (curl_errno($httpClient)) {
            $returnResponse->addError("Curl error: " . curl_error($httpClient));
            curl_close($httpClient); // release resource
            return $returnResponse;
        }
        curl_close($httpClient); // release resource

        try {
            $decodeAsAssociativeArray = true;
            $maxDepthOfDecoding = 3;
            /** @var array $response throws JsonException if something went wrong */
            $gDecodedResponse = json_decode(
                $rawGoogleResponse,
                $decodeAsAssociativeArray,
                $maxDepthOfDecoding,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            $returnResponse->addError("Json decoding error: " . $e->getMessage());
            return $returnResponse;
        }

        /** @var bool $responseSuccess */
        $responseSuccess = (bool)$gDecodedResponse['success'];
        /** @var float $responseScore */
        $responseScore = floatval($gDecodedResponse['score']);
        /** @var string $responseHostname */
        $responseHostname = $gDecodedResponse['hostname'];
        /** @var string $responseAction */
        $responseAction = $gDecodedResponse['action'];

        if ($responseSuccess === false) {
            if (isset($gDecodedResponse['error-codes'])) {
                /** @var string[] $responseAction */
                $responseErrorCodes = $gDecodedResponse['error-codes'];
                foreach ($responseErrorCodes as $errorCode) {
                    $returnResponse->addError(self::getErrorTextByCode($errorCode));
                }
                return $returnResponse;
            }
        }

        if (
            empty($responseSuccess) ||
            empty($responseScore) ||
            empty($responseHostname) ||
            empty($responseAction)
        ) {
            throw new GRecaptchaGoogleResponseValidationException(); // "Impossible" ? - do not trust Google - it is an evil :-)
        }

        $returnResponse->fill(
            $responseSuccess,
            $responseScore,
            $responseHostname,
            $responseAction
        );

        return $returnResponse;
    }

    /**
     * @param string $errorCode
     * @return string
     */
    public static function getErrorTextByCode(string $errorCode): string
    {
        $result = '';
        switch ($errorCode) {
            case static::INVALID_INPUT_RESPONSE :
                $result = 'The response parameter is invalid or malformed.';
                break;
            case static::MISSING_INPUT_SECRET:
                $result = 'The secret parameter is missing.';
                break;
            case static::INVALID_INPUT_SECRET:
                $result = 'The secret parameter is invalid or malformed.';
                break;
            case static::MISSING_INPUT_RESPONSE:
                $result = 'The response parameter is missing.';
                break;
            case static::BAD_REQUEST:
                $result = 'The request is invalid or malformed.';
                break;
            case static:: TIMEOUT_OR_DUPLICATE:
                $result = 'The response is no longer valid: either is too old or has been used previously.';
                break;
            default:
                $result = 'Unknown error code';
                break;
        }

        return $result;
    }

}


/**
 * Class GRecaptchaApi
 * @author Sergey ksb@itksb.com
 */
final class GRecaptchaApi
{
    /** @var string $recaptchaSecret */
    private $recaptchaSecret;
    /** @var float minScore */
    private $minScore;
    /** @var string $hostname */
    private $hostname;
    /** @var string $action */
    private $action;
    /** @var @var GRecaptchaHttpClientInterface $httpClient */
    private $httpClient;

    /**
     * GRecaptchaApi constructor.
     * @param string $recaptchaSecret
     * @param float $minScore
     * @param string $hostname
     */
    final public function __construct(
        string $recaptchaSecret,
        float $minScore = 0.5,
        string $hostname = '',
        string $action = ''
    )
    {
        $this->setRecaptchaSecret($recaptchaSecret);
        $this->setHostname($hostname);
        $this->setMinScore($minScore);
        $this->setAction($action);
        return $this;
    }

    /**
     * @param string $recaptchaSecret
     * @return $this
     */
    final public function setRecaptchaSecret(string $recaptchaSecret): GRecaptchaApi
    {
        if (empty($recaptchaSecret)) {
            throw new InvalidArgumentException('Recaptcha secret is not set');
        };
        $this->recaptchaSecret = $recaptchaSecret;
        return $this;
    }

    /**
     * @param string $hostname
     * @return $this
     */
    final public function setHostname(string $hostname): GRecaptchaApi
    {
        $this->hostname = $hostname;
        return $this;
    }

    /**
     * @param float $minScore
     * @return $this
     */
    final public function setMinScore(float $minScore): GRecaptchaApi
    {
        $this->minScore = $minScore;
        return $this;
    }

    /**
     * @param string $action
     * @return $this
     */
    public function setAction(string $action): GRecaptchaApi
    {
        $this->action = $action;
        return $this;
    }

    /**
     * Validates Google recaptcha
     * @param string $captchaResponse response from the client
     * @param string $clientIpAddress client IP address
     * @return bool
     */
    final public function validate(string $captchaResponse, string $clientIpAddress = ''): bool
    {
        /** @var bool $returnResult */
        $returnResult = false;
        // sanitizing input
        $captchaResponse = $this->sanitizeInCaptchaResponse($captchaResponse);
        $clientIpAddress = $this->sanitizeInClientIpAddress($clientIpAddress);

        /** @var bool $isValidInput */
        $isValidInput = mb_strlen($captchaResponse);
        if (!$isValidInput) {
            throw new InvalidArgumentException('One or more of required gRecaptcha arguments is empty.');
        }

        $httpClient = $this->getHttpClient();
        $gResponse = $httpClient->sendRequest(
            $this->recaptchaSecret,
            $captchaResponse,
            $clientIpAddress
        );
        if ($gResponse->hasErrors()) {
            throw new GRecaptchaValidationException(
                'Errors during request occured: '
                . implode('. ', $gResponse->getErrors())
            );
        }

        $returnResult = $gResponse->isSuccess();
        $returnResult = $returnResult && ($gResponse->getScore() >= $this->minScore);
        if (!empty($this->hostname)) {
            $returnResult = $returnResult && ($gResponse->getHostname() === $this->hostname);
        }
        if (!empty($this->action)) {
            $returnResult = $returnResult && ($gResponse->getAction() === $this->action);
        }

        return $returnResult;
    }

    private function sanitizeInCaptchaResponse(string $response)
    {
        return filter_var($response, FILTER_SANITIZE_STRING);
    }

    private function sanitizeInClientIpAddress(string $ip)
    {
        return filter_var($ip, FILTER_SANITIZE_STRING);
    }

    /**
     * @return GRecaptchaHttpClientInterface
     * @throws Exception
     */
    private function getHttpClient(): GRecaptchaHttpClientInterface
    {
        if (empty($this->httpClient)) {
            throw new  Exception('Http client is no set.');
        }
        return $this->httpClient;
    }

    /**
     * @param GRecaptchaHttpClientInterface $httpClient
     * @return GRecaptchaApi
     */
    final public function setHttpClient(GRecaptchaHttpClientInterface $httpClient): GRecaptchaApi
    {
        $this->httpClient = $httpClient;
        return $this;
    }


}

/**
 * Class GRecaptchaGoogleResponseValidationException
 * @author Sergey ksb@itksb.com
 */
final class GRecaptchaGoogleResponseValidationException extends Exception
{
    public function __construct()
    {
        parent::__construct('Grecaptcha resonse from Google does not contain required attributes');
    }
}

/**
 * Class GRecaptchaValidationException
 * @author Sergey ksb@itksb.com
 */
final class GRecaptchaValidationException extends Exception
{
}

