class GiroError(ValueError):
    """An expected validation or unsupported-protocol error, safe to display."""


class ResponseError(GiroError):
    def __init__(self, code, *, error_info=None, callback_code=None, origin="response"):
        self.code = code
        self.error_info = error_info
        self.origin = origin
        # The app prefers errorInfo.errorCode even when it is empty/null.
        self.callback_code = (error_info.get("errorCode") if error_info is not None
                              else callback_code if origin == "model_decode" else code)
        super().__init__("서비스 응답의 처리 기준에서 실패")
