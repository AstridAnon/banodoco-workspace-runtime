class RuntimeErrorBase(Exception):
    code = "runtime_error"
    status = 400

    def __init__(self, message: str, *, details=None):
        super().__init__(message)
        self.message = message
        self.details = details

    def as_dict(self):
        result = {"code": self.code, "message": self.message}
        if self.details is not None:
            result["details"] = self.details
        return result


class AuthorizationError(RuntimeErrorBase):
    code = "unauthorized"
    status = 401


class ConflictError(RuntimeErrorBase):
    code = "conflict"
    status = 409


class ValidationError(RuntimeErrorBase):
    code = "validation_error"
    status = 422


class ForbiddenError(RuntimeErrorBase):
    code = "forbidden"
    status = 403


class CapabilityUnavailableError(ConflictError):
    """Admission failed because the registered capability is not ready."""

    # Keep Astrid's frozen SDK taxonomy.  The capability-specific reason and
    # next action are carried in bounded details, not a new machine code.
    code = "unavailable"


class NotFoundError(RuntimeErrorBase):
    code = "not_found"
    status = 404


class OwnerBusyError(ConflictError):
    code = "owner_busy"


class RealmAdmissionError(ConflictError):
    """An existing realm failed the bounded, read-only startup gate."""

    code = "realm_admission_failed"


class LeaseError(ConflictError):
    code = "lease_fenced"


class ProtocolError(RuntimeErrorBase):
    code = "protocol_error"
    status = 400


class InvalidRequestError(RuntimeErrorBase):
    """A syntactically valid request with an invalid JSON shape."""

    code = "invalid_request"
    status = 400
