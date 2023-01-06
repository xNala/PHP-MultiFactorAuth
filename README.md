
# PHP MultiFactorAuth Class




An easy to integrate single class PHP library to interface with Google Authenticator or Authy.  
It provides a full set of functions for generating and validating 2FA codes.  
The library allows developers to provide better security for their end users by using either Google Authenticator or Authy as an authentication service.  
A function to generate a QR Code is provided for the given secret.

## Authors

- [xNala](https://github.com/xNala/)


## Features

- Secret Generation
- Code Verification
- QR Code Generation
## Deployment

Once the secret is generated, it should be stored in the database for the user.  
After the user has succesfully entered a code from Authy/Google Auth is when you should enable MFA for their account. Not before then.  
Demonstration of the functions.  

```php
  <?php
    require_once ('_MFA_Functions.php');

    
    $mfaFunctions = new MFAFunctions();

    echo '<html><body>';
    $secret = $mfaFunctions->generateSecret(32);
    echo "<p>User's 2FA secret is: ".$secret."</p>";;

    $otpCode = $mfaFunctions->calculateCode($secret);
    echo "<p>Secret's Current OTP: ".$otpCode."</p>";

    $qrLink = $mfaFunctions->generateQRCode('TestName', $secret, 100);

    echo '<img src="'.$qrLink.'"></img>';

    $compareResult = $mfaFunctions->compareCode($secret, $otpCode, 2);
    if($compareResult)
        echo "<p>CHECK PASSED</p>";
    else
        echo "<p>CHECK FAILED</p>";

    echo '</body></html>';

?>
```

