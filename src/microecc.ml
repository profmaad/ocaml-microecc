open Ctypes;;
open Foreign;;

module Curve = struct
  module T = struct
    type t
    let t : t structure typ = structure "uECC_Curve_t"
  end
  type t = T.t structure ptr
  let t = ptr T.t

  let private_key_size = foreign "uECC_curve_private_key_size" (t @-> returning int)
  let public_key_size  = foreign "uECC_curve_public_key_size"  (t @-> returning int)

  let curve_size t = (public_key_size t) / 2

  let compressed_point_size t = curve_size t + 1
  let shared_secret_size      = curve_size
  let signature_size          = public_key_size

  let secp160r1 = foreign "uECC_secp160r1" (void @-> returning t)
  let secp192r1 = foreign "uECC_secp192r1" (void @-> returning t)
  let secp224r1 = foreign "uECC_secp224r1" (void @-> returning t)
  let secp256r1 = foreign "uECC_secp256r1" (void @-> returning t)
  let secp256k1 = foreign "uECC_secp256k1" (void @-> returning t)
end

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

let make_key_c = foreign "uECC_make_key" (ptr uint8_t @-> ptr uint8_t @-> Curve.t @-> returning int);;
let make_key curve =
  let public_key_array  = CArray.make uint8_t (Curve.public_key_size curve)  in
  let private_key_array = CArray.make uint8_t (Curve.private_key_size curve) in
  let result = make_key_c (CArray.start public_key_array) (CArray.start private_key_array) curve in
  let public_key  = string_of_uint8_array public_key_array  (Curve.public_key_size curve)  in
  let private_key = string_of_uint8_array private_key_array (Curve.private_key_size curve) in
  match result with
  | 1 -> Some (`Public_key public_key, `Private_key private_key)
  | _ -> None
;;

let shared_secret_c = foreign "uECC_shared_secret" (ptr uint8_t @-> ptr uint8_t @-> ptr uint8_t @-> Curve.t @-> returning int);;
let shared_secret curve ~opposite_public_key ~private_key =
  let public_key_array = char_array_of_string opposite_public_key in
  let private_key_array = char_array_of_string private_key in
  let shared_secret_array = CArray.make uint8_t (Curve.shared_secret_size curve) in
  let result = shared_secret_c (uint8_ptr_of_char_array public_key_array) (uint8_ptr_of_char_array private_key_array) (CArray.start shared_secret_array) curve in
  let shared_secret_string = string_of_uint8_array shared_secret_array (Curve.shared_secret_size curve) in
  match result with
  | 1 -> Some shared_secret_string
  | _ -> None
;;

let compress_c = foreign "uECC_compress" (ptr uint8_t @-> ptr uint8_t @-> Curve.t @-> returning void);;
let compress curve ~public_key =
  let public_key_array = char_array_of_string public_key in
  let compressed_point_array = CArray.make uint8_t (Curve.compressed_point_size curve) in
  compress_c (uint8_ptr_of_char_array public_key_array) (CArray.start compressed_point_array) curve;
  string_of_uint8_array compressed_point_array (Curve.compressed_point_size curve)
;;

let decompress_c = foreign "uECC_decompress" (ptr uint8_t @-> ptr uint8_t @-> Curve.t @-> returning void);;
let decompress curve ~compressed_point =
  let compressed_point_array = char_array_of_string compressed_point in
  let public_key_array = CArray.make uint8_t (Curve.public_key_size curve) in
  decompress_c (uint8_ptr_of_char_array compressed_point_array) (CArray.start public_key_array) curve;
  string_of_uint8_array public_key_array (Curve.public_key_size curve)
;;

let sign_c = foreign "uECC_sign" (ptr uint8_t @-> ptr uint8_t @-> uint @-> ptr uint8_t @-> Curve.t @-> returning int);;
let sign curve ~private_key ~hash =
  let private_key_array = char_array_of_string private_key in
  let hash_array = char_array_of_string hash in
  let hash_size  = String.length hash in
  let signature_array = CArray.make uint8_t (Curve.signature_size curve) in
  let result =
    sign_c
      (uint8_ptr_of_char_array private_key_array)
      (uint8_ptr_of_char_array hash_array)
      (Unsigned.UInt.of_int hash_size)
      (CArray.start signature_array)
      curve
  in
  let signature = string_of_uint8_array signature_array (Curve.signature_size curve) in
  match result with
  | 1 -> Some signature
  | _ -> None
;;

let verify_c = foreign "uECC_verify" (ptr uint8_t @-> ptr uint8_t @-> uint @-> ptr uint8_t @-> Curve.t @-> returning int);;
let verify curve ~public_key ~hash ~signature =
  let public_key_array = char_array_of_string public_key in
  let hash_array = char_array_of_string hash in
  let hash_size = String.length hash in
  let signature_array = char_array_of_string signature in
  let result =
    verify_c
      (uint8_ptr_of_char_array public_key_array)
      (uint8_ptr_of_char_array hash_array)
      (Unsigned.UInt.of_int hash_size)
      (uint8_ptr_of_char_array signature_array)
      curve
  in
  match result with
  | 1 -> true
  | _ -> false
;;
