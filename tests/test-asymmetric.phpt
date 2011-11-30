<?php
	$skip_keygen = false;
	$keysize = 1024;
	$salt = 'salt';
	$password = 'password';
	$password2 = 'passwore';
	$orig = 'This is some kind of some long and pretty even longer text that is being used just for testing purposes of minCrypt algorithm system. ';
	$orig .= 'This is some text text text text text text text text text text text text text text text text text text text text text text text text';
	$size = strlen($orig);

	require_once('functions.phpt');

	function generate_keys($keysize, $salt, $password, $keyfile_prefix) {
		$ret = mincrypt_generate_keys($keysize, $salt, $password, $keyfile_prefix.'.key', $keyfile_prefix.'.pub');
		if (!$ret)
			return mincrypt_get_last_error();

		return true;
	}

	function asymmetric_encrypt($infile, $outfile, $public_key, $salt, $password) {
		if (!mincrypt_read_key($public_key))
			return mincrypt_get_last_error();

		if (!mincrypt_set_password($password, $salt))
			return mincrypt_get_last_error();

		if (!mincrypt_encrypt_file($infile, $outfile))
			return mincrypt_get_last_error();

		return true;
	}

	function asymmetric_decrypt($infile, $outfile, $private_key, $salt, $password) {
		if (!mincrypt_read_key($private_key))
			return mincrypt_get_last_error();

		if (!mincrypt_set_password($password, $salt))
			return mincrypt_get_last_error();

		if (!mincrypt_decrypt_file($infile, $outfile))
			return mincrypt_get_last_error();

		return true;
	}

	if (!$skip_keygen) {
		$ret = generate_keys($keysize, $salt, $password, 'test-key1');
		if (!$ret)
			echo "ERROR: ".$ret;
	}

	$highlevel_ok = false;
	$highlevel_fail = false;
	if (asymmetric_encrypt('test.tgz', 'tmp1', 'test-key1.key', $salt, $password)) {
		if (asymmetric_decrypt('tmp1', 'tmp2', 'test-key1.pub', $salt, $password))
			$highlevel_ok = true;
		if (asymmetric_decrypt('tmp1', 'tmp2', 'test-key1.pub', $salt, $password2))
			$highlevel_fail = true;
	}

	mincrypt_reset_id();

	mincrypt_read_key('test-key1.pub');
	mincrypt_set_password($password, $salt);
	$size = strlen($orig);
	$in = mincrypt_encrypt($orig, $size);
	mincrypt_reset_id();
	$size = mincrypt_last_size();
	mincrypt_read_key('test-key1.key');
	mincrypt_set_password($password, $salt);
	$out = mincrypt_decrypt($in, $size);
	$lowlevel_ok = ($out == $orig);

	mincrypt_read_key('test-key1.key');
	mincrypt_set_password($password2, $salt);
	$out = mincrypt_decrypt($in, $size);
	$lowlevel_fail = ($out != $orig);

	/* Test on file */
	mincrypt_read_key('test-key1.pub');
	mincrypt_set_password($password, $salt);
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
	unlink('test-key1.pub');
	unlink('test-key1.key');

	if ((!($highlevel_ok && $highlevel_fail && $lowlevel_ok && $lowlevel_fail && $lowlevel_file))
		|| (is_string($highlevel_fail) || is_string($highlevel_ok))){
		echo "High-level API test: ".($highlevel_ok ?
			(is_string($highlevel_ok) ? $highlevel_ok : "Success") : "Failed")."\n";
		echo "High-level API fail test: ".($highlevel_fail ?
			(is_string($highlevel_fail) ? $highlevel_fail : "Success") : "Failed")."\n";
		echo "Low-level API test: ".($lowlevel_ok ? "Success" : "Failed")."\n";
		echo "Low-level API fail test: ".($lowlevel_fail ? "Success" : "Failed")."\n";
		echo "Low-level file API test: ".($lowlevel_file ? "Success" : "Failed")."\n";

		bail("At least one of tests failed\n");
	}

	success( basename(__FILE__) );
	exit(0);
?>
