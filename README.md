# php-google-recaptcha-v3

Wrapper on the Google Recaptcha V3 API for verification grecaptcha site response. 


## Usage
                                 
It is written for the legacy project, so composer package manager is not used. 
  

``
require_once 'GRecaptchaApi.php';
``

In your controller or service or etc:

```
$api = new GRecaptchaApi(
    $secret,    // site secret key 
    $minScore,  // minimum score [0.1 - 1] 
    $hostname
);

// you can use my simple HttpClient
$api->setHttpClient(
    new GRecaptchaCurlHttpClient()
);

//or just implement GRecaptchaHttpClientInterface:
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

// Thats it! Client code:

if ($api->validate($captchaResponse, $clientIpAddress)) {
   echo 'Ok, you are not a bot.';
} {
   echo 'Sorry. We cannot trust your request';
}

```
     
Also see usage example in the GRecaptchaService.php file.
   


## License 

MIT
