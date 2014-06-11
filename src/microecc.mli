val make_key : unit -> (string * string) option

val shared_secret : string -> string -> string option

val compress : string -> string

val decompress : string -> string

val sign : string -> string -> string option

val verify : string -> string -> string -> bool
