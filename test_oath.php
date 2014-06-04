<?php
 
 /***********************************************************************
     * Sample PHP code testing OATH-PHP
	 * Made by IRETH S.R.L. (http://www.ireth.net/)
     * 
	 * This sample code has no warranty, it is provided “as is”. 
	 * It is your responsibility to validate the behaviour of the routines 
	 * and their accuracy.
	 *
	 * The authors take no responsibility for any consequences that may 
	 * arise from using this code.
	 * 
     * @package oath    
     * @author Walter Summonte
     * @version 1.0
     * @access public
	 * 
	 * Please send any contributions at support@ireth.net
*************************************************************************/
 
 include('oath.php');
  
 $key20 = hex2bin('3132333435363738393031323334353637383930');
 $key32 = hex2bin('3132333435363738393031323334353637383930313233343536373839303132');
 $key64 = hex2bin('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
 $pin =   hex2bin('7110eda4d09e062aa5e4a390b0a572ac0d2c0220'); 
 $timestep = 30;
///////////////////////////////////////////////////
echo "<pre>";
echo "Test HOTP (RFC4226)\n\r";
echo "Count\tHexadecimal\tDecimal\tHOTP\n\r";

for ($i=0;$i<10;$i++)
{
$counter = base_convert($i, 10, 16);
$counter = str_pad($counter,16 ,"0", STR_PAD_LEFT);
$counter = hex2bin($counter);

$dec = hotp($key20, $counter);
$hex = base_convert($dec, 10, 16);
if (strlen($hex) < 8) $hex.=' '; // pad to format output
$otp = substr($dec,-6);

echo "$i\t$hex\t$dec\t$otp\n\r";
}
/////////////////////////////////////////////////////
echo "\n\r\n\rTest TOTP (RFC4226)\n\r";
echo "Time\t\tValue of T\t\tTOTP\t\tMode\n\r";
date_default_timezone_set("UTC");
$t = 59;
$utc = date('Y-m-d G:i:s',$t);
$counter=bcdiv($t , $timestep, 0); 
$counter = base_convert($counter, 10, 16); 
$counter1 = str_pad($counter,16,"0", STR_PAD_LEFT); 
$counter=hex2bin($counter1);

$algo="sha1";
$totp = substr(totp($key20,$timestep,$algo,$t),-8);
echo "$t\t\t$counter1\t$totp\t$algo\n\r";
$algo="sha256";
$totp = substr(totp($key32,$timestep,$algo,$t),-8);
echo "$t\t\t$counter1\t$totp\t$algo\n\r";
$algo="sha512";
$totp = substr(totp($key64,$timestep,$algo,$t),-8);
echo "$t\t\t$counter1\t$totp\t$algo\n\r";

$t = 1111111109;
$counter=bcdiv($t , $timestep, 0); 
$counter = base_convert($counter, 10, 16); 
$counter1 = str_pad($counter,16,"0", STR_PAD_LEFT); 
$counter=hex2bin($counter1);

$algo="sha1";
$totp = substr(totp($key20,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha256";
$totp = substr(totp($key32,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha512";
$totp = substr(totp($key64,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
 
$t= 1111111111;
$counter=bcdiv($t , $timestep, 0); 
$counter = base_convert($counter, 10, 16); 
$counter1 = str_pad($counter,16,"0", STR_PAD_LEFT); 
$counter=hex2bin($counter1);

$algo="sha1";
$totp = substr(totp($key20,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha256";
$totp = substr(totp($key32,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha512";
$totp = substr(totp($key64,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";

$t=1234567890;
$counter=bcdiv($t , $timestep, 0); 
$counter = base_convert($counter, 10, 16); 
$counter1 = str_pad($counter,16,"0", STR_PAD_LEFT); 
$counter=hex2bin($counter1);

$algo="sha1";
$totp = substr(totp($key20,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha256";
$totp = substr(totp($key32,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha512";
$totp = substr(totp($key64,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";

$t=2000000000;
$counter=bcdiv($t , $timestep, 0); 
$counter = base_convert($counter, 10, 16); 
$counter1 = str_pad($counter,16,"0", STR_PAD_LEFT); 
$counter=hex2bin($counter1);

$algo="sha1";
$totp = substr(totp($key20,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha256";
$totp = substr(totp($key32,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha512";
$totp = substr(totp($key64,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";

$t=20000000000;
$counter=bcdiv($t , $timestep, 0); 
$counter = base_convert($counter, 10, 16); 
$counter1 = str_pad($counter,16,"0", STR_PAD_LEFT); 
$counter=hex2bin($counter1);

$algo="sha1";
$totp = substr(totp($key20,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha256";
$totp = substr(totp($key32,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
$algo="sha512";
$totp = substr(totp($key64,$timestep,$algo,$t),-8);
echo "$t\t$counter1\t$totp\t$algo\n\r";
 
///////////////////////////////////////////////////
echo "Test OCRA (RFC6287)\n\r";
echo"\n\rSuite: OCRA-1:HOTP-SHA1-6:QN08\n\r";
echo "Q\t\tRESPONSE\n\r";
$suite="OCRA-1:HOTP-SHA1-6:QN08";
$q =00000000;
$response = ocra($key20,$suite,$q);
echo "$q\t\t$response\n\r";
$q =11111111;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =22222222;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =33333333;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =44444444;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =55555555;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =66666666;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =77777777;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =88888888;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
$q =99999999;
$response = ocra($key20,$suite,$q);
echo "$q\t$response\n\r";
 
echo"\n\rSuite: OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1\n\r";
echo "C\tQ\t\tRESPONSE\n\r";
$suite="OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
$q =12345678;
$c=0;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=1;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=2;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=3;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=4;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=5;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=6;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=7;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=8;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";
$c=9;
$response = ocra($key32,$suite,$q,$c,$pin);
echo "$c\t$q\t$response\n\r";

 
echo"\n\rSuite: OCRA-1:HOTP-SHA256-8:QN08-PSHA1\n\r";
echo "Q\t\t\tRESPONSE\n\r";
$suite="OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
$q =00000000;
$response = ocra($key32,$suite,$q,null,$pin);
echo "$q\t\t\t$response\n\r";
$q =11111111;
$response = ocra($key32,$suite,$q,null,$pin);
echo "$q\t\t$response\n\r";
$q =22222222;
$response = ocra($key32,$suite,$q,null,$pin);
echo "$q\t\t$response\n\r";
$q =33333333;
$response = ocra($key32,$suite,$q,null,$pin);
echo "$q\t\t$response\n\r";
$q =44444444;
$response = ocra($key32,$suite,$q,null,$pin);
echo "$q\t\t$response\n\r";


echo"\n\rSuite: OCRA-1:HOTP-SHA512-8:C-QN08\n\r";
echo "C\nQ\t\t\t\tRESPONSE\n\r";
$suite="OCRA-1:HOTP-SHA512-8:C-QN08";
$q =00000000;
$c=0;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t\t$response\n\r";
$q =11111111;
$c=1;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =22222222;
$c=2;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =33333333;
$c=3;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =44444444;
$c=4;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =55555555;
$c=5;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =66666666;
$c=6;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =77777777;
$c=7;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =88888888;
$c=8;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";
$q =99999999;
$c=9;
$response = ocra($key64,$suite,$q,$c);
echo "$c\t$q\t\t$response\n\r";


echo"\n\rSuite: OCRA-1:HOTP-SHA512-8:QN08-T1M\n\r";
echo "Q\t\tT\t\t\tRESPONSE\n\r";
$suite="OCRA-1:HOTP-SHA512-8:QN08-T1M";
$t=hexdec('0132d0b6');
$t=bcmul($t , 60);
$q =00000000;
$response = ocra($key64,$suite,$q,null,null,null,$t);
echo "$q\t\t0132d0b6\t\t$response\n\r";
$q =11111111;
$response = ocra($key64,$suite,$q,null,null,null,$t);
echo "$q\t0132d0b6\t\t$response\n\r";
$q =22222222;
$response = ocra($key64,$suite,$q,null,null,null,$t);
echo "$q\t0132d0b6\t\t$response\n\r";
$q =33333333;
$response = ocra($key64,$suite,$q,null,null,null,$t);
echo "$q\t0132d0b6\t\t$response\n\r";
$q =44444444;
$response = ocra($key64,$suite,$q,null,null,null,$t);
echo "$q\t0132d0b6\t\t$response\n\r";
echo "</pre>";



	
 ?>
