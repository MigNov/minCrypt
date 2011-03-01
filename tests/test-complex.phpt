<?php
	require_once('functions.phpt');

	$orig = 'This is some kind of some long and pretty even longer text that is being used just for testing purposes of minCrypt algorithm system. ';
	$orig .= 'This is some text text text text text text text text text text text text text text text text text text text text text text text text';
	$password = 'password';
	$password2 = 'passwore';
	$salt = 'salt';
	$mult = 128;

	if (!mincrypt_set_password($password, $salt, $mult))
		echo "ERROR: ".mincrypt_get_last_error();

	mincrypt_reset_id();
	$size = strlen($orig);
	$in = mincrypt_encrypt($orig, $size);
	mincrypt_reset_id();
	$size = strlen($in);
	$out = mincrypt_decrypt($in, $size);

	$lowlevel_ok = ($out == $orig);

	mincrypt_set_password($password2, $salt, $mult);
	$out = mincrypt_decrypt($in, $size);

	$lowlevel_fail = ($out != $orig);

	if (!mincrypt_set_password($password, $salt, $mult))
		echo "ERROR: ".mincrypt_get_last_error();

	$highlevel_ok = false;
	$highlevel_fail = false;
	$rc = mincrypt_encrypt_file('test.tgz', 'tmp1');
	if ($rc == 0) {
		$rc = mincrypt_decrypt_file('tmp1', 'tmp2');
		if ($rc == 0)
			$highlevel_ok = true;

		mincrypt_set_password($password2, $salt, $mult);
		$rc = mincrypt_decrypt_file('tmp1', 'tmp3');
		$highlevel_fail = ($rc != 0);
	}	

	/* Test on file */
	mincrypt_set_password($password, $salt, $mult);
	$lowlevel_file = true;
	$free = true;
	$fp = fopen('test.tgz', 'r');
	$fp2 = fopen('tmp1', 'w');
	$oldpos = 0;
	while ( ($str = fread($fp, 64)) != false ) {
		$num_read = ftell($fp) - $oldpos;
		$oldpos = ftell($fp);

		$out = mincrypt_encrypt($str, $num_read);
		$esize = mincrypt_last_size();

		if ( ($s = fwrite($fp2, $out, $esize)) != $esize) {
			$lowlevel_file = false;
			fclose($fp);
			fclose($fp2);
			$free = false;
			unlink('tmp1');
		}
  	}

	if ($free) {
		fclose($fp);
		fclose($fp2);
	}

	unlink('tmp1');
	unlink('tmp2');
	unlink('tmp3');

	if (!($highlevel_ok && $highlevel_fail && $lowlevel_ok && $lowlevel_fail && $lowlevel_file)) {
		echo "High-level API test: ".($highlevel_ok ? "Success" : "Failed")."\n";
		echo "High-level API fail test: ".($highlevel_fail ? "Success" : "Failed")."\n";
		echo "Low-level API test: ".($lowlevel_ok ? "Success" : "Failed")."\n";
		echo "Low-level API fail test: ".($lowlevel_fail ? "Success" : "Failed")."\n";
		echo "Low-level file API test: ".($lowlevel_file ? "Success" : "Failed")."\n";

		bail("At least one of tests failed\n");
	}

	success( basename(__FILE__) );
	exit(0);
?>
