<?php
/**
 * This is a sample oAuth flow you can follow in your application.
 */

use Zendesk\API\Utilities\OAuth;

include("../../vendor/autoload.php");

if (isset($_POST['action']) && 'redirect' === $_POST['action']) {
    $state = base64_encode(serialize($_POST));

    // Get the oAuth URI using the utility function
    $oAuthUrl= OAuth::getAuthUrl(
        $_POST['subdomain'],
        [
            'client_id' => $_POST['client_id'],
            'state' => $state,
        ]
    );

    header('Location: ' . $oAuthUrl);
} elseif (isset($_REQUEST['code'])) {
    /**
     * This block acts as the redirect_uri, once you receive an authorization_code ($_GET['code']).
     */

    $params = unserialize(base64_decode($_GET['state']));
    $params['code'] = $_REQUEST['code'];
    $params['redirect_uri'] = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];

    try {
        // Request for an access token by passing an instance of GuzzleHttp\Client, your Zendesk subdomain, and the
        // following params ['client_id', 'client_secret', 'redirect_uri']

        $response = OAuth::getAccessToken(new GuzzleHttp\Client(), $params['subdomain'], $params);
        echo "<h1>Success!</h1>";
        echo "<p>Your OAuth token is: " . $response->access_token . "</p>";
        echo "<p>Use this code before any other API call:</p>";
        echo "<code>&lt;?php<br />\$client = new ZendeskAPI(\$subdomain);<br />\$client->setAuth(\Zendesk\API\Utilities\Auth::OAUTH, ['token' => " . $response->access_token . "]');<br />?&gt;</code>";
    } catch (\Zendesk\API\Exceptions\ApiResponseException $e) {
        echo "<h1>Error!</h1>";
        echo "<p>We couldn't get an access token for you. Please check your credentials and try again.</p>";
        echo "<p>" . $e->getMessage() . "</p>";
    }
} else {
    // A simple form to help you get started.
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <!-- Latest compiled and minified CSS -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <form id="form-oauth" method="POST">
                    <input type="hidden" name="action" value="redirect"/>

                    <div class="form-group">
                        <label for="subdomain">Subdomain</label>
                        <input type="text" class="form-control" name="subdomain" placeholder="Your Zendesk subdomain"
                               required/>
                    </div>
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" class="form-control"
                               placeholder="Your Zendesk login" required/>
                    </div>
                    <div class="form-group">
                        <label for="client_id">Client ID</label>
                        <input type="text" id="client_id" class="form-control" name="client_id"
                               placeholder="Your oAuth Client ID" required/>
                    </div>
                    <div class="form-group">
                        <label for="client_secret">Client Secret</label>
                        <input type="text" id="client_secret" class="form-control" name="client_secret" required/>
                    </div>
                    <button type="submit" class="btn btn-default">Submit</button>
                </form>
            </div>
        </div>
    </div>
    </body>
    </html>

    <?php

}
