<?php

    class MFAFunctions{

        protected $maxCodeLength = 6;


        //Generate User Secret.
        function generateSecret($length)
        {
            if(!is_numeric($length)) //Not Numeric
                return false;

            if($length < 32 || $length > 128) //Invalid Length.
                return false;                 //Length should be greater than 32, but less than 128.

            $generatedSecret = '';

            $validCharacters = $this->base32Array(); //Get the array of BASE32 characters.

            $randomBytes = false;

            if(function_exists('random_bytes'))
                // https://www.php.net/manual/en/function.random-bytes
                $randomBytes = random_bytes($length); //If the random_bytes function exists, default to that.

            elseif (function_exists('mcrypt_create_iv'))
                // https://www.php.net/manual/en/function.mcrypt-create-iv
                $randomBytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM); //if random_bytes doesn't exist, attempt mcrypt_create_iv

            elseif(function_exists('openssl_random_pseudo_bytes')) 
            {
                // https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php
                $randomBytes = openssl_random_pseudo_bytes($length, $strong); //If the above functions don't exist, fall back to openssl_random_pseudo_bytes

                if(!$strong) //strong_result returned false. Not secure.
                    $randomBytes = false;
            }

            if($randomBytes !== false)
            {
                $integer = 0;
                while($length-->0) //Create a loop that counts up to the max secret length
                { 
                    // https://www.php.net/manual/en/function.ord.php
                    $generatedSecret .= $validCharacters[ord($randomBytes[$integer]) & 31];
                    $integer++;
                } 
            }else
            {
                //No Secure Random Function Found.
                return false;
            }

            return $generatedSecret;
        }


        //Compare Secret And Code
        function compareCode($secret, $code, $timeDiscrepenancy = 1, $timePeriod = null)
        {
            if($timePeriod === null)
                // https://www.php.net/manual/en/function.floor.php
                // https://www.php.net/manual/en/function.time.php
                $timePeriod = floor(time() / 30);

                if(strlen($code) != $this->maxCodeLength)
                    return false;
                
                for($integer = -$timeDiscrepenancy; $integer <= $timeDiscrepenancy; $integer++){
                    $calculatedCode = $this->calculateCode($secret, $timePeriod + $integer);

                    if($this->timingSafeEquals($calculatedCode, $code))
                        return true;
                }

            return false;
        }


        //Calculate the current 2FA code with the secret and time period provided.
        function calculateCode($secret, $timePeriod = null)
        {
            if($timePeriod === null)
                // https://www.php.net/manual/en/function.floor.php
                // https://www.php.net/manual/en/function.time.php
                $timePeriod = floor(time() / 30);


                //decode the secret from base32
                $key = $this->decodeBase32($secret);

                // https://www.php.net/manual/en/function.chr
                // https://www.php.net/manual/en/function.pack
                $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timePeriod); //convert the time to a binary string

                // https://www.php.net/manual/en/function.hash-hmac.php
                $hash = hash_hmac('SHA1', $time, $key, true); //generate an HMAC hash for the time and key


                // https://www.php.net/manual/en/function.substr
                // https://www.php.net/manual/en/function.ord.php
                $offset = ord(substr($hash, -1, 4)) & 0x0F; //getting the last bit of the result as an offset

                // https://www.php.net/manual/en/function.substr
                $hashpart = substr($hash, $offset, 4); //grabbing 4 bytes of the result

                //https://www.php.net/manual/en/function.unpack
                $unpacked = unpack('N', $hashpart);
                $unpacked = $unpacked[1];

                //Convert to only 32 bits
                $unpacked = $unpacked & 0x7FFFFFFF;

                //modulooooo
                //https://www.php.net/manual/en/function.pow
                $modulo = pow(10, $this->maxCodeLength);

                //https://www.php.net/manual/en/function.str-pad
                return str_pad($unpacked % $modulo, $this->maxCodeLength, '0', STR_PAD_LEFT);
        }


        //Returns a BASE32 Character Array
        //Library of BASE32 and BASE64 characters https://www.garykessler.net/library/base64.html
        function base32Array()
        {
            return array('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '=');
        }


        //Provide a BASE32 input and it will return a decoded output.
        function decodeBase32($input){
            if(empty($input))
                return false;

            $base32Characters = $this->base32Array();

            // https://www.php.net/manual/en/function.array-flip.php
            $base32CharactersFlipped = array_flip($base32Characters);

            // https://www.php.net/manual/en/function.substr-count
            $paddingCount = substr_count($input, $base32Characters[32]);

            $allowedPaddingValues = array(6, 4, 2, 1, 0);

            // https://www.php.net/manual/en/function.in-array.php
            if(!in_array($paddingCount, $allowedPaddingValues)) //Compare the padding count
                return false;

            $integer = 0;
            $integerMax = 4;
            while($integerMax-->0) //Create a loop that counts up to the max length
            {
                // https://www.php.net/manual/en/function.substr
                // https://www.php.net/manual/en/function.str-repeat
                if($paddingCount == $allowedPaddingValues[$integer] && substr($input, -($allowedPaddingValues[$integer])) != str_repeat($base32Characters[32], $allowedPaddingValues[$integer]))
                    return false; 

                $integer++;
            }

            // https://www.php.net/manual/en/function.str-repeat
            $input = str_replace('=', '', $input);

            // https://www.php.net/manual/en/function.str-split 
            $input = str_split($input);

            $binaryValue = '';

            for($integer = 0; $integer < count($input); $integer = $integer + 8)
            {
                $tmp = '';

                // https://www.php.net/manual/en/function.in-array.php
                if(!in_array($input[$integer], $base32Characters))
                    return false;

                for($integer2 = 0; $integer2 < 8; $integer2++)
                    // https://www.php.net/manual/en/function.str-pad
                    $tmp .= str_pad(base_convert(@$base32CharactersFlipped[$input[$integer + $integer2]], 10, 2), 5, '0', STR_PAD_LEFT);

                // https://www.php.net/manual/en/function.str-split 
                $bits = str_split($tmp, 8);

                for($integer3 = 0; $integer3 < count($bits); $integer3++)
                    // https://www.php.net/manual/en/function.chr
                    $binaryValue .= (($tmp2 = chr(base_convert($bits[$integer3], 2, 10))) || ord($tmp2) == 48) ? $tmp2 : '';



            }

            return $binaryValue;
        }


        function generateQRCode($otpName, $secret, $size = 300)
        {
            if(!is_numeric($size))
                return false;

            $otpUrl = urlencode('otpauth://totp/'.$otpName.'?secret='.$secret.'');

            return "https://api.qrserver.com/v1/create-qr-code/?data=".$otpUrl."&size=".$size."x".$size."&ecc=M";


        }


        //IRCMaxwell's Timing Safe function for basic codeflow
        //http://blog.ircmaxell.com/2014/11/its-all-about-time.html
        //We love blogs <3
        function timingSafeEquals($safe, $user)
        {
            $safeLen = strlen($safe);
            $userLen = strlen($user);
        
            if ($userLen != $safeLen) {
                return false;
            }
        
            $result = 0;
        
            $integer = 0;
            while($userLen-->0) //Create a loop that counts up to the max length
            {
                // https://www.php.net/manual/en/function.ord.php
                $result |= (ord($safe[$integer]) ^ ord($user[$integer]));
                $integer++;
            }

            // They are only identical strings if $result is exactly 0...
            return $result === 0;
        }
    }







?>