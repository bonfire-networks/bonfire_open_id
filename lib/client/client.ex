defmodule Bonfire.OpenID.Client do
  import Untangle
  alias Bonfire.Common.Utils

  def open_id_connect_providers,
    do:
      Application.get_env(:bonfire_open_id, :openid_connect_providers, [])
      |> Enum.map(fn {provider, config} ->
        {provider, config |> Enum.into(%{redirect_uri: provider_url(provider, :openid)})}
      end)

  def oauth2_providers,
    do:
      Application.get_env(:bonfire_open_id, :oauth2_providers, [])
      |> Enum.map(fn {provider, config} ->
        {provider, config |> Enum.into(%{redirect_uri: provider_url(provider, :oauth)})}
      end)

  def providers_authorization_urls(source \\ :login) do
    #  provider_url(provider, :openid)
    (for {provider, config} <- open_id_connect_providers() do
       unless source == :signup and config[:only_supports_login],
         do: {
           config[:display_name] || provider,
           config[:redirect_uri]
         }
     end ++
       for {provider, config} <- oauth2_providers() do
         unless source == :signup and config[:only_supports_login],
           do: {
             config[:display_name] || provider,
             config[:redirect_uri]
             #  provider_url(provider, :oauth)
           }
       end)
    |> Enum.reject(&is_nil/1)
  end

  defp provider_url(provider, type) do
    "#{Bonfire.Common.URIs.base_url()}/#{type}/client/#{provider}"
  end

  def link_provider_token(current_user, provider, provider_token) do
    case Bonfire.Common.Cache.get(provider_token) do
      {:ok, %{} = provider_params} ->
        link_provider_alias(current_user, provider, provider_params)

        Bonfire.Common.Cache.remove(provider_token)

      other ->
        err(other, "No data for token #{inspect(provider_token)}")
        :ok
    end
  end

  def link_provider_alias(current_user, provider, params) do
    Utils.maybe_apply(Bonfire.Social.Graph.Aliases, :add, [
      current_user,
      {:provider, provider, params},
      [update_existing: true]
    ])
  end
end
