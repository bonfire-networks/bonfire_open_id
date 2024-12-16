defmodule Bonfire.OpenID.Client do
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
end
