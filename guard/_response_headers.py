from collections.abc import Iterable, Mapping

from starlette.responses import Response

HeaderList = list[tuple[bytes, bytes]]


def merge_vary(existing: Iterable[str], required: str) -> str:
    present = ", ".join(value for value in existing if value.strip())
    if not present:
        return required
    tokens = {token.strip().lower() for token in present.split(",")}
    if tokens & {required.lower(), "*"}:
        return present
    return f"{present}, {required}"


def _named(headers: HeaderList, lowered: str) -> list[bytes]:
    return [value for key, value in headers if key.lower() == lowered.encode("latin-1")]


def _without(headers: HeaderList, lowered: str) -> HeaderList:
    return [pair for pair in headers if pair[0].lower() != lowered.encode("latin-1")]


def _appended(headers: HeaderList, lowered: str, value: str) -> HeaderList:
    return [*headers, (lowered.encode("latin-1"), value.encode("latin-1"))]


def with_default_headers(
    headers: HeaderList, defaults: Mapping[str, str], forced: frozenset[str]
) -> HeaderList:
    merged = list(headers)
    for name, value in defaults.items():
        lowered = name.lower()
        if lowered in forced:
            merged = _without(merged, lowered)
        elif _named(merged, lowered):
            continue
        merged = _appended(merged, lowered, value)
    return merged


def with_cors_headers(headers: HeaderList, cors: Mapping[str, str]) -> HeaderList:
    """Guard's CORS headers replace the response's of the same name (the engine's
    contract); `Vary` is merged, never replaced."""
    merged = list(headers)
    for name, value in cors.items():
        lowered = name.lower()
        if lowered == "vary":
            value = merge_vary(
                [v.decode("latin-1") for v in _named(merged, lowered)], value
            )
        merged = _appended(_without(merged, lowered), lowered, value)
    return merged


def apply_cors_to_response(response: Response, cors: Mapping[str, str]) -> None:
    """The same semantics as `with_cors_headers`, for a Starlette response."""
    for key, value in cors.items():
        if key.lower() == "vary":
            value = merge_vary(response.headers.getlist("vary"), value)
        response.headers[key] = value
