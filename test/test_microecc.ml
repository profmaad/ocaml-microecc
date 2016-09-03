open Microecc;;

let print_hex_string s =
  let hex_iterator c =
    Printf.printf "%02x " (int_of_char c);
  in
  String.iter hex_iterator s
;;
let print_hex_string_with_prefix s prefix =
  let prefix_string = Printf.sprintf "%s (%d bytes):" prefix (String.length s) in
  let tabs_count = 5 - ((String.length prefix_string) / 8) in
  let tabs = String.make tabs_count '\t' in
  Printf.printf "%s%s" prefix_string tabs; print_hex_string s; print_newline ()
;;

let generate_random_hash length =
  let hash = String.make length '\x00' in
  for i = 0 to length - 1 do
    Bytes.set hash i (Char.chr (Random.int 256))
  done;
  hash
;;

let compression_test public_key =
  print_endline "Running compression/decompression test...";
  let compressed_pubkey = compress public_key in
  print_hex_string_with_prefix compressed_pubkey "Compressed public key";
  let decompressed_pubkey = decompress compressed_pubkey in
  print_hex_string_with_prefix decompressed_pubkey "Decompressed public key";
  if (compare public_key decompressed_pubkey) = 0 then
    (print_endline "PASSED"; true)
  else
    (print_endline "FAILED"; false)
;;

let ecdsa_test public_key private_key =
  print_endline "Running ECDSA signature generation/verification test...";
  let hash = generate_random_hash 32 in
  print_hex_string_with_prefix hash "Hash";
  match sign private_key hash with
  | None -> print_endline "FAILED: Signature generation failed"; false
  | Some signature ->
    print_hex_string_with_prefix signature "Signature";
    match verify public_key hash signature with
    | true -> print_endline "PASSED"; true
    | false -> print_endline "FAILED: Signature verification failed"; false
;;

let ecdh_test public_key_1 private_key_1 =
  print_endline "Running ECDH test...";
  match make_key () with
  | None -> print_endline "FAILED: Key generation failed"; false
  | Some (public_key_2, private_key_2) ->
    match shared_secret public_key_2 private_key_1 with
    | None -> print_endline "FAILED: shared secret generation 1"; false
    | Some shared_secret_1 ->
      print_hex_string_with_prefix shared_secret_1 "Shared Secret 1";
      match shared_secret public_key_1 private_key_2 with
      | None -> print_endline "FAILED: shared secret generation 2"; false
      | Some shared_secret_2 ->
	print_hex_string_with_prefix shared_secret_2 "Shared Secret 2";
	if (compare shared_secret_1 shared_secret_2) = 0 then
	  (print_endline "PASSED"; true)
	else
	  (print_endline "FAILED: shared secrets don't match"; false)
;;

let int_of_bool = function
  | false -> 0
  | true -> 1
;;

let () =
  Random.self_init ();
  match make_key () with
  | None -> print_endline "Key generation failed"
  | Some (public_key, private_key) ->
    print_hex_string_with_prefix public_key "Public key";
    print_hex_string_with_prefix private_key "Private key";
    print_newline ();
    let passed = ref 0 in
    passed := !passed + int_of_bool (compression_test public_key);
    print_newline ();
    passed := !passed + int_of_bool (ecdsa_test public_key private_key);
    print_newline ();
    passed := !passed + int_of_bool (ecdh_test public_key private_key);
    print_newline ();
    Printf.printf "RESULTS: %d passed, %d failed\n" !passed (3 - !passed);
    exit (3 - !passed)
;;
