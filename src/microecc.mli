(** OCaml bindings for the micro-ecc library, implementing ECDH and ECDSA.
    All vlaues in this module are handled as binary strings. *)

module Curve : sig
  type t

  val secp160r1 : t
  val secp192r1 : t
  val secp224r1 : t
  val secp256r1 : t
  val secp256k1 : t

  val private_key_size : t -> int
  val public_key_size  : t -> int
end

(** Generates a new ECC keypair, if successful.
    @return If successful, returns Some (public_key, private_key). None otherwise *)
val make_key : Curve.t -> (string * string) option

(** Generates the ECDH shared secret given the other parties public key and our private key
    @return If successful, returns Some shared_secret, None otherwise. *)
val shared_secret : Curve.t -> string -> string -> string option

(** Compresses the given public key into the compressed point representation
    @return compressed point representation of the given public key *)
val compress : Curve.t -> string -> string

(** Decompresses a public key in compressed point form
    @return the decompressed public key *)
val decompress : Curve.t -> string -> string

(** Given a private key and a hash, it signs the hash and returns the signature.
    Signatures are given as two points, r and s, concatenated into one string.
    Please note that this does not return DER representation as used by OpenSSL.
    @return Some signature if successful, None otherwise *)
val sign : Curve.t -> string -> string -> string option

(** Given a public key, a hash and a signature, it verifies the signature against the hash and public key.
    The signature is expected to be in the same format returned by sign, not in DER format.
    @return true if the signature was verified successfully, false otherwise. *)
val verify : Curve.t -> string -> string -> string -> bool
