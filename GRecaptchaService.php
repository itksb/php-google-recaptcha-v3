<?php
declare(strict_types=1);

require_once 'GRecaptchaApi.php';

/**
 * Class GRecaptchaService
 * @author Sergey ksb@itksb.com
 */
class GRecaptchaService extends CApplicationComponent
{
    /** @var string $secret */
    public $secret;
    /** @var float $minScore */
    public $minScore;
    /** @var string $secret */
    public $hostname;
    /** @var GRecaptchaApi $api */
    protected $api;

    public function init()
    {
        parent::init();

    }

    /**
     * Validate
     * @param string $captchaResponse
     * @param string $clientIpAddress
     * @return bool
     * @throws GRecaptchaValidationException
     */
    public function validate(string $captchaResponse, string $clientIpAddress = ''): bool
    {
        $api = $this->getApi();
        return $api->validate($captchaResponse, $clientIpAddress);
    }

    /**
     * @return GRecaptchaApi
     */
    protected function getApi(): GRecaptchaApi
    {
        if (!$this->api instanceof GRecaptchaApi) {
            $this->api = new GRecaptchaApi(
                $this->secret,
                $this->minScore,
                $this->hostname
            );
            $this->api->setHttpClient(
                new GRecaptchaCurlHttpClient()
            );
        }
        return $this->api;
    }

}

