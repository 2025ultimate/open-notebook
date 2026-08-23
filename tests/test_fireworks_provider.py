"""Wiring tests for the Fireworks AI provider.

Fireworks has no native esperanto driver: it is served through esperanto's
`openai-compatible` provider pinned to Fireworks' serverless endpoint. These
tests lock down that indirection — the alias, the pinned base URL, the
credential/env key paths and the required-key guard — because none of it is
exercised by the generic registry tests.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from open_notebook.ai.provider_registry import FIREWORKS_DEFAULT_BASE_URL, PROVIDERS
from open_notebook.domain.credential import Credential
from open_notebook.exceptions import ConfigurationError


class TestRegistryEntry:
    def test_fireworks_is_registered_with_openai_compatible_discovery(self):
        spec = PROVIDERS["fireworks"]
        assert spec.display_name == "Fireworks AI"
        assert spec.required_env == ("FIREWORKS_API_KEY",)
        assert spec.modalities == ("language", "embedding")
        assert spec.openai_compat_discovery_url == (
            f"{FIREWORKS_DEFAULT_BASE_URL}/models"
        )

    def test_test_model_is_dynamic(self):
        # Fireworks publishes no floating alias and retires model ids, so the
        # connection test lists /models rather than calling a pinned model.
        assert PROVIDERS["fireworks"].test_model is None

    def test_supported_provider_literal_includes_fireworks(self):
        from typing import get_args

        from api.models import SupportedProvider

        assert "fireworks" in get_args(SupportedProvider)


class TestModelProvisioning:
    @pytest.mark.asyncio
    async def test_credential_maps_to_openai_compatible_with_pinned_base_url(self):
        from open_notebook.ai.models import Model, ModelManager

        credential = Credential(
            name="Fireworks",
            provider="fireworks",
            api_key=SecretStr("fw-test"),
        )
        model = Model(
            id="model:test",
            name="accounts/fireworks/models/llama-v3p1-8b-instruct",
            provider="fireworks",
            type="language",
            credential="credential:test",
        )
        factory_model = SimpleNamespace()

        with (
            patch.object(Model, "get", AsyncMock(return_value=model)),
            patch.object(
                Model, "get_credential_obj", AsyncMock(return_value=credential)
            ),
            patch(
                "open_notebook.ai.models.AIFactory.create_language",
                return_value=factory_model,
            ) as create_language,
        ):
            result = await ModelManager().get_model("model:test")

        assert result is factory_model
        create_language.assert_called_once_with(
            model_name="accounts/fireworks/models/llama-v3p1-8b-instruct",
            provider="openai-compatible",
            config={
                "api_key": "fw-test",
                "base_url": FIREWORKS_DEFAULT_BASE_URL,
            },
        )

    @pytest.mark.asyncio
    async def test_credential_base_url_overrides_the_pinned_default(self):
        """A dedicated Fireworks deployment can override the serverless URL."""
        from open_notebook.ai.models import Model, ModelManager

        credential = Credential(
            name="Fireworks dedicated",
            provider="fireworks",
            api_key=SecretStr("fw-test"),
            base_url="https://example.fireworks.ai/inference/v1",
        )
        model = Model(
            id="model:test",
            name="custom-model",
            provider="fireworks",
            type="language",
            credential="credential:test",
        )

        with (
            patch.object(Model, "get", AsyncMock(return_value=model)),
            patch.object(
                Model, "get_credential_obj", AsyncMock(return_value=credential)
            ),
            patch("open_notebook.ai.models.validate_url", AsyncMock()),
            patch(
                "open_notebook.ai.models.AIFactory.create_language"
            ) as create_language,
        ):
            await ModelManager().get_model("model:test")

        assert create_language.call_args.kwargs["config"]["base_url"] == (
            "https://example.fireworks.ai/inference/v1"
        )

    @pytest.mark.asyncio
    async def test_unlinked_model_falls_back_to_env_api_key(self, monkeypatch):
        from open_notebook.ai.models import Model, ModelManager

        monkeypatch.setenv("FIREWORKS_API_KEY", "fw-from-env")
        model = Model(
            id="model:test",
            name="accounts/fireworks/models/llama-v3p1-8b-instruct",
            provider="fireworks",
            type="language",
        )

        with (
            patch.object(Model, "get", AsyncMock(return_value=model)),
            patch(
                "open_notebook.ai.key_provider.provision_provider_keys",
                AsyncMock(return_value=False),
            ),
            patch(
                "open_notebook.ai.models.AIFactory.create_language"
            ) as create_language,
        ):
            await ModelManager().get_model("model:test")

        create_language.assert_called_once_with(
            model_name="accounts/fireworks/models/llama-v3p1-8b-instruct",
            provider="openai-compatible",
            config={
                "api_key": "fw-from-env",
                "base_url": FIREWORKS_DEFAULT_BASE_URL,
            },
        )

    @pytest.mark.asyncio
    async def test_kwargs_do_not_suppress_the_env_fallback(self, monkeypatch):
        """A kwarg like temperature must not make `config` truthy too early."""
        from open_notebook.ai.models import Model, ModelManager

        monkeypatch.setenv("FIREWORKS_API_KEY", "fw-from-env")
        model = Model(
            id="model:test",
            name="fw-model",
            provider="fireworks",
            type="language",
        )

        with (
            patch.object(Model, "get", AsyncMock(return_value=model)),
            patch(
                "open_notebook.ai.key_provider.provision_provider_keys",
                AsyncMock(return_value=False),
            ),
            patch(
                "open_notebook.ai.models.AIFactory.create_language"
            ) as create_language,
        ):
            await ModelManager().get_model("model:test", temperature=0.5)

        config = create_language.call_args.kwargs["config"]
        assert config["api_key"] == "fw-from-env"
        assert config["temperature"] == 0.5

    @pytest.mark.asyncio
    async def test_missing_api_key_raises_configuration_error(self, monkeypatch):
        """ConfigurationError (not ValueError) so the API answers 422."""
        from open_notebook.ai.models import Model, ModelManager

        monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
        model = Model(
            id="model:test",
            name="fw-model",
            provider="fireworks",
            type="language",
        )

        with (
            patch.object(Model, "get", AsyncMock(return_value=model)),
            patch(
                "open_notebook.ai.key_provider.provision_provider_keys",
                AsyncMock(return_value=False),
            ),
            pytest.raises(ConfigurationError, match="require an API key"),
        ):
            await ModelManager().get_model("model:test")


class TestModelClassification:
    @pytest.mark.parametrize(
        ("model_id", "expected"),
        [
            ("accounts/fireworks/models/llama-v3p1-8b-instruct", "language"),
            ("accounts/fireworks/models/qwen3-235b-a22b", "language"),
            ("nomic-ai/nomic-embed-text-v1.5", "embedding"),
            ("thenlper/gte-large", "embedding"),
            ("WhereIsAI/UAE-Large-V1", "embedding"),
        ],
    )
    def test_classifies_embedding_models_apart_from_language(self, model_id, expected):
        from open_notebook.ai.model_discovery import classify_model_type

        assert classify_model_type(model_id, "fireworks") == expected


class TestCredentialConnectionTest:
    @pytest.mark.asyncio
    async def test_test_credential_uses_pinned_url_when_none_configured(self):
        from api import credentials_service

        credential = Credential(
            id="credential:test",
            name="Fireworks",
            provider="fireworks",
            api_key=SecretStr("fw-test"),
        )

        with (
            patch.object(
                credentials_service.Credential,
                "get",
                AsyncMock(return_value=credential),
            ),
            patch(
                "open_notebook.ai.connection_tester._test_openai_compatible_connection",
                AsyncMock(return_value=(True, "Connected. 2 models available")),
            ) as tester,
        ):
            result = await credentials_service.test_credential("credential:test")

        assert result == {
            "provider": "fireworks",
            "success": True,
            "message": "Connected. 2 models available",
        }
        tester.assert_awaited_once_with(FIREWORKS_DEFAULT_BASE_URL, "fw-test")
