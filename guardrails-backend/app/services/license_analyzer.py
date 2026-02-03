import uuid
import re
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.license import (
    LicenseRequest,
    LicenseResponse,
    SimilarityRequest,
    SimilarityResponse,
    DetectedLicense,
    LicenseStatus,
    SimilarityMatch,
)


# Common license patterns in file headers
LICENSE_PATTERNS = {
    "MIT": [
        r"MIT License",
        r"Permission is hereby granted, free of charge",
        r"SPDX-License-Identifier:\s*MIT",
    ],
    "Apache-2.0": [
        r"Apache License.*Version 2\.0",
        r"Licensed under the Apache License",
        r"SPDX-License-Identifier:\s*Apache-2\.0",
    ],
    "GPL-3.0": [
        r"GNU General Public License.*version 3",
        r"GPLv3",
        r"SPDX-License-Identifier:\s*GPL-3\.0",
    ],
    "BSD-3-Clause": [
        r"BSD 3-Clause License",
        r"Redistribution and use in source and binary forms",
        r"SPDX-License-Identifier:\s*BSD-3-Clause",
    ],
    "ISC": [
        r"ISC License",
        r"SPDX-License-Identifier:\s*ISC",
    ],
    "AGPL-3.0": [
        r"GNU Affero General Public License",
        r"AGPL",
        r"SPDX-License-Identifier:\s*AGPL-3\.0",
    ],
}


class LicenseAnalyzerService:
    """Service for license and IP compliance analysis."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_licenses(self, request: LicenseRequest) -> LicenseResponse:
        """Check license compliance for provided files."""
        check_id = str(uuid.uuid4())
        detected_licenses: list[DetectedLicense] = []
        compliant_count = 0
        non_compliant_count = 0
        review_count = 0

        for file in request.files:
            detected = self._detect_license(file.content, file.path)

            if detected:
                status = self._determine_status(
                    detected["license_id"],
                    request.allowed_licenses,
                    request.blocked_licenses,
                )

                detected_licenses.append(DetectedLicense(
                    file_path=file.path,
                    license_id=detected["license_id"],
                    license_name=detected["license_name"],
                    status=status,
                    confidence=detected["confidence"],
                    source=detected["source"],
                ))

                if status == LicenseStatus.ALLOWED:
                    compliant_count += 1
                elif status == LicenseStatus.BLOCKED:
                    non_compliant_count += 1
                else:
                    review_count += 1

        # Determine overall status
        if non_compliant_count > 0:
            overall_status = "non_compliant"
        elif review_count > 0:
            overall_status = "review_required"
        else:
            overall_status = "compliant"

        recommendations = self._generate_recommendations(detected_licenses)

        return LicenseResponse(
            check_id=check_id,
            status=overall_status,
            total_files=len(request.files),
            compliant_count=compliant_count,
            non_compliant_count=non_compliant_count,
            review_count=review_count,
            detected_licenses=detected_licenses,
            recommendations=recommendations,
            created_at=datetime.utcnow(),
        )

    async def check_similarity(self, request: SimilarityRequest) -> SimilarityResponse:
        """Check code similarity for IP risks."""
        check_id = str(uuid.uuid4())

        # Placeholder implementation - in production, this would use
        # code similarity detection tools like ScanCode or custom fingerprinting
        matches: list[SimilarityMatch] = []

        # Simple heuristic: check for common copied patterns
        copied_patterns = [
            (r"Copyright.*\d{4}.*(?!your-org)", "Potential external copyright"),
            (r"@author\s+[^your-team]", "External author attribution"),
        ]

        has_similar = False
        for pattern, source in copied_patterns:
            if re.search(pattern, request.code, re.IGNORECASE):
                has_similar = True
                matches.append(SimilarityMatch(
                    source=source,
                    similarity_score=0.7,
                    matched_lines=[],
                    license=None,
                    risk_level="medium",
                ))

        ip_risk = "low"
        if len(matches) > 0:
            ip_risk = "medium" if matches[0].similarity_score < 0.9 else "high"

        recommendations = []
        if has_similar:
            recommendations.append("Review code origin and ensure proper attribution")
            recommendations.append("Verify license compatibility with your project")

        return SimilarityResponse(
            check_id=check_id,
            file_path=request.file_path,
            has_similar_code=has_similar,
            matches=matches,
            ip_risk_assessment=ip_risk,
            recommendations=recommendations,
            created_at=datetime.utcnow(),
        )

    def _detect_license(self, content: str, file_path: str) -> dict | None:
        """Detect license in file content."""
        # Check first 100 lines for license headers
        lines = content.split("\n")[:100]
        header = "\n".join(lines)

        for license_id, patterns in LICENSE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, header, re.IGNORECASE):
                    return {
                        "license_id": license_id,
                        "license_name": self._get_license_name(license_id),
                        "confidence": 0.9,
                        "source": "file_header",
                    }

        # Check for package.json license field
        if file_path.endswith("package.json"):
            import json
            try:
                pkg = json.loads(content)
                if "license" in pkg:
                    license_id = pkg["license"]
                    return {
                        "license_id": license_id,
                        "license_name": self._get_license_name(license_id),
                        "confidence": 1.0,
                        "source": "package.json",
                    }
            except json.JSONDecodeError:
                pass

        return None

    def _get_license_name(self, license_id: str) -> str:
        """Get full license name from SPDX identifier."""
        names = {
            "MIT": "MIT License",
            "Apache-2.0": "Apache License 2.0",
            "GPL-2.0": "GNU General Public License v2.0",
            "GPL-3.0": "GNU General Public License v3.0",
            "BSD-2-Clause": "BSD 2-Clause License",
            "BSD-3-Clause": "BSD 3-Clause License",
            "ISC": "ISC License",
            "AGPL-3.0": "GNU Affero General Public License v3.0",
            "LGPL-2.1": "GNU Lesser General Public License v2.1",
            "LGPL-3.0": "GNU Lesser General Public License v3.0",
        }
        return names.get(license_id, license_id)

    def _determine_status(
        self,
        license_id: str,
        allowed: list[str],
        blocked: list[str],
    ) -> LicenseStatus:
        """Determine license status based on policy."""
        if license_id in blocked:
            return LicenseStatus.BLOCKED
        if license_id in allowed:
            return LicenseStatus.ALLOWED
        return LicenseStatus.REVIEW

    def _generate_recommendations(
        self,
        licenses: list[DetectedLicense],
    ) -> list[str]:
        """Generate recommendations based on detected licenses."""
        recommendations = []
        blocked = [l for l in licenses if l.status == LicenseStatus.BLOCKED]
        review = [l for l in licenses if l.status == LicenseStatus.REVIEW]

        if blocked:
            recommendations.append(
                f"Remove or replace {len(blocked)} file(s) with blocked licenses"
            )
            for l in blocked[:3]:
                recommendations.append(f"  - {l.file_path}: {l.license_id}")

        if review:
            recommendations.append(
                f"Review {len(review)} file(s) with unclassified licenses"
            )

        return recommendations
