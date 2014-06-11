open Ctypes;;
open Foreign;;

let bytes = 32;;
let public_key_length = 2 * bytes;;
let private_key_length = bytes;;
let shared_secret_length = bytes;;
let compressed_point_length = bytes + 1;;
let hash_length = bytes;;
let signature_length = 2 * bytes;;

let char_array_of_string s =
  let length = String.length s in
  let array = CArray.make char length in
  for i = 0 to length - 1 do
    CArray.set array i (s.[i])
  done;
  array
;;
let uint8_ptr_of_char_array a = coerce (ptr char) (ptr uint8_t) (CArray.start a);;
let string_of_uint8_array a length =
  string_from_ptr
    (coerce (ptr uint8_t) (ptr char) (CArray.start a))
    ~length:length
;;

let make_key_c = foreign "uECC_make_key" (ptr uint8_t @-> ptr uint8_t @-> returning int);;
let make_key () = 
  let public_key_array = CArray.make uint8_t public_key_length in
  let private_key_array = CArray.make uint8_t private_key_length in
  let result = make_key_c (CArray.start public_key_array) (CArray.start private_key_array) in
  let public_key = string_of_uint8_array public_key_array public_key_length in
  let private_key = string_of_uint8_array private_key_array private_key_length in
  match result with
  | 1 -> Some (public_key, private_key)
  | _ -> None
;;

let shared_secret_c = foreign "uECC_shared_secret" (ptr uint8_t @-> ptr uint8_t @-> ptr uint8_t @-> returning int);;
let shared_secret opposite_public_key private_key =
  let public_key_array = char_array_of_string opposite_public_key in
  let private_key_array = char_array_of_string private_key in
  let shared_secret_array = CArray.make uint8_t shared_secret_length in
  let result = shared_secret_c (uint8_ptr_of_char_array public_key_array) (uint8_ptr_of_char_array private_key_array) (CArray.start shared_secret_array) in
  let shared_secret_string = string_of_uint8_array shared_secret_array shared_secret_length in
  match result with
  | 1 -> Some shared_secret_string
  | _ -> None
;;

let compress_c = foreign "uECC_compress" (ptr uint8_t @-> ptr uint8_t @-> returning void);;
let compress public_key =
  let public_key_array = char_array_of_string public_key in
  let compressed_point_array = CArray.make uint8_t compressed_point_length in
  compress_c (uint8_ptr_of_char_array public_key_array) (CArray.start compressed_point_array);
  string_of_uint8_array compressed_point_array compressed_point_length
;;

let decompress_c = foreign "uECC_decompress" (ptr uint8_t @-> ptr uint8_t @-> returning void);;
let decompress compressed_point =
  let compressed_point_array = char_array_of_string compressed_point in
  let public_key_array = CArray.make uint8_t public_key_length in
  decompress_c (uint8_ptr_of_char_array compressed_point_array) (CArray.start public_key_array);
  string_of_uint8_array public_key_array public_key_length
;;

let sign_c = foreign "uECC_sign" (ptr uint8_t @-> ptr uint8_t @-> ptr uint8_t @-> returning int);;
let sign private_key hash =
  let private_key_array = char_array_of_string private_key in
  let hash_array = char_array_of_string hash in
  let signature_array = CArray.make uint8_t signature_length in
  let result = sign_c (uint8_ptr_of_char_array private_key_array) (uint8_ptr_of_char_array hash_array) (CArray.start signature_array) in
  let signature = string_of_uint8_array signature_array signature_length in
  match result with
  | 1 -> Some signature
  | _ -> None
;;

let verify_c = foreign "uECC_verify" (ptr uint8_t @-> ptr uint8_t @-> ptr uint8_t @-> returning int);;
let verify public_key hash signature =
  let public_key_array = char_array_of_string public_key in
  let hash_array = char_array_of_string hash in
  let signature_array = char_array_of_string signature in
  match verify_c (uint8_ptr_of_char_array public_key_array) (uint8_ptr_of_char_array hash_array) (uint8_ptr_of_char_array signature_array) with
  | 1 -> true
  | _ -> false
;;
