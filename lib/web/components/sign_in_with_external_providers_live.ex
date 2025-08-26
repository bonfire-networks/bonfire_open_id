defmodule Bonfire.OpenID.Web.SignInWithExternalProvidersLive do
  use Bonfire.UI.Common.Web, :stateless_component

  prop label, :any, default: nil
  prop source, :atom, default: nil
  prop include_providers, :list, default: nil

  def filter_providers(providers, nil), do: providers
  def filter_providers(providers, []), do: providers

  def filter_providers(providers, include_providers) when is_list(include_providers) do
    Enum.filter(providers, fn {provider, _} -> provider in include_providers end)
  end
end
