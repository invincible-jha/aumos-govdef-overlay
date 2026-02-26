"""Service-specific settings for aumos-govdef-overlay.

All standard AumOS configuration is inherited from AumOSSettings.
Govdef-specific settings use the AUMOS_GOVDEF_ env prefix.
"""

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Settings for aumos-govdef-overlay.

    Inherits all standard AumOS settings (database, kafka, keycloak, etc.)
    and adds Government/Defense compliance configuration.

    Environment variable prefix: AUMOS_GOVDEF_
    """

    service_name: str = "aumos-govdef-overlay"

    # FedRAMP configuration
    fedramp_agency_id: str = Field(
        default="",
        description="Federal agency identifier for FedRAMP authorization tracking",
    )
    fedramp_impact_level: str = Field(
        default="moderate",
        description="FedRAMP impact level: low, moderate, or high",
    )
    fedramp_pmo_contact: str = Field(
        default="",
        description="FedRAMP PMO contact email for authorization coordination",
    )

    # NIST 800-53 configuration
    nist_baseline: str = Field(
        default="moderate",
        description="NIST 800-53 baseline: low, moderate, or high",
    )
    nist_revision: str = Field(
        default="rev5",
        description="NIST SP 800-53 revision: rev4 or rev5",
    )

    # CMMC configuration
    cmmc_target_level: int = Field(
        default=3,
        description="CMMC target certification level: 1, 2, or 3",
    )
    cmmc_c3pao_id: str = Field(
        default="",
        description="Certified Third-Party Assessment Organization identifier",
    )

    # Sovereign cloud configuration
    sovereign_cloud_provider: str = Field(
        default="",
        description="Sovereign cloud provider: aws-govcloud, azure-government, gcc-high",
    )
    sovereign_region: str = Field(
        default="",
        description="Sovereign cloud deployment region",
    )

    # Impact level configuration
    max_il_level: int = Field(
        default=4,
        description="Maximum Impact Level supported: 4 or 5",
    )
    classified_env_encryption_key_arn: str = Field(
        default="",
        description="ARN of KMS key for classified environment data encryption",
    )

    model_config = SettingsConfigDict(env_prefix="AUMOS_GOVDEF_")
