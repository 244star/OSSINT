from .models import Confidence, IdentifierType


def classify(finding_count: int, independent_sources: int, ident_type: str) -> Confidence:
    if ident_type == IdentifierType.NAME.value:
        # names are inherently collision-prone: require strong corroboration
        return Confidence.VERIFIED if independent_sources >= 3 else Confidence.LIKELY
    if finding_count >= 1 and independent_sources >= 2:
        return Confidence.VERIFIED
    return Confidence.LIKELY if finding_count else Confidence.UNSURE
