package us.berkovitz.stoken

class InvalidDeviceIdException(err: String): Exception(err) {}

class PasswordRequiredException(err: String): Exception(err) {}
