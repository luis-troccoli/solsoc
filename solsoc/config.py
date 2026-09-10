from __future__ import annotations
import os
from dotenv import load_dotenv
from solsoc.llm.base import LLMProvider

load_dotenv()

PROVIDERS = ("anthropic", "openai", "gemini")


def get_provider(name: str) -> LLMProvider:
    """Instantiate and return the requested LLM provider."""
    name = name.lower()

    if name == "anthropic":
        from solsoc.llm.anthropic_provider import AnthropicProvider
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set. Add it to your .env file.")
        return AnthropicProvider(api_key=api_key)

    elif name == "openai":
        from solsoc.llm.openai_provider import OpenAIProvider
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set. Add it to your .env file.")
        return OpenAIProvider(api_key=api_key)

    elif name == "gemini":
        from solsoc.llm.gemini_provider import GeminiProvider
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set. Add it to your .env file.")
        return GeminiProvider(api_key=api_key)

    else:
        raise ValueError(
            f"Unknown provider '{name}'. Choose from: {', '.join(PROVIDERS)}"
        )


def get_wazuh_integration(
    url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_ssl: bool | None = None,
):
    from solsoc.integrations.wazuh import WazuhIntegration
    _url = url or os.getenv("WAZUH_URL", "")
    _user = username or os.getenv("WAZUH_USER", "wazuh-wui")
    _pass = password or os.getenv("WAZUH_PASSWORD", "")
    _ssl = verify_ssl if verify_ssl is not None else (
        os.getenv("WAZUH_VERIFY_SSL", "true").lower() != "false"
    )
    if not _url:
        raise ValueError("WAZUH_URL is not set. Add it to your .env or pass --url.")
    if not _pass:
        raise ValueError("WAZUH_PASSWORD is not set. Add it to your .env or pass --password.")
    return WazuhIntegration(url=_url, username=_user, password=_pass, verify_ssl=_ssl)


def get_sentinel_integration(
    subscription_id: str | None = None,
    resource_group: str | None = None,
    workspace_name: str | None = None,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
):
    from solsoc.integrations.sentinel import SentinelIntegration
    _sub = subscription_id or os.getenv("SENTINEL_SUBSCRIPTION_ID", "")
    _rg = resource_group or os.getenv("SENTINEL_RESOURCE_GROUP", "")
    _ws = workspace_name or os.getenv("SENTINEL_WORKSPACE_NAME", "")
    _tid = tenant_id or os.getenv("AZURE_TENANT_ID")
    _cid = client_id or os.getenv("AZURE_CLIENT_ID")
    _cs = client_secret or os.getenv("AZURE_CLIENT_SECRET")
    if not _sub:
        raise ValueError("SENTINEL_SUBSCRIPTION_ID is not set.")
    if not _rg:
        raise ValueError("SENTINEL_RESOURCE_GROUP is not set.")
    if not _ws:
        raise ValueError("SENTINEL_WORKSPACE_NAME is not set.")
    return SentinelIntegration(
        subscription_id=_sub,
        resource_group=_rg,
        workspace_name=_ws,
        tenant_id=_tid,
        client_id=_cid,
        client_secret=_cs,
    )


def get_splunk_integration(
    url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    query: str | None = None,
    verify_ssl: bool | None = None,
):
    from solsoc.integrations.splunk import SplunkIntegration
    _url = url or os.getenv("SPLUNK_URL", "")
    _user = username or os.getenv("SPLUNK_USER", "")
    _pass = password or os.getenv("SPLUNK_PASSWORD", "")
    _query = query or os.getenv("SPLUNK_QUERY")
    _ssl = verify_ssl if verify_ssl is not None else (
        os.getenv("SPLUNK_VERIFY_SSL", "true").lower() != "false"
    )
    if not _url:
        raise ValueError("SPLUNK_URL is not set. Add it to your .env or pass --url.")
    if not _user:
        raise ValueError("SPLUNK_USER is not set. Add it to your .env or pass --username.")
    if not _pass:
        raise ValueError("SPLUNK_PASSWORD is not set. Add it to your .env or pass --password.")
    return SplunkIntegration(url=_url, username=_user, password=_pass, query=_query, verify_ssl=_ssl)
