defmodule Bonfire.OpenID.Client do
  import Untangle
  use Arrows
  use Bonfire.Common.Localise
  alias Bonfire.Common.Utils
  alias Bonfire.Common.Types

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

  def providers() do
    open_id_connect_providers() ++ oauth2_providers()
  end

  def providers_for(source \\ :login) do
    providers()
    |> Enum.reject(fn {_provider, config} ->
      source == :signup and config[:only_supports_login]
    end)
  end

  def provider_config(provider) do
    with provider when is_atom(provider) <- Types.maybe_to_atom(provider) do
      open_id_connect_providers()[provider] || oauth2_providers()[provider]
    end
  end

  def providers_authorization_urls(source \\ :login) do
    for {provider, config} <- providers_for(source) do
      {
        config[:display_name] || provider,
        config[:redirect_uri]
        #  provider_url(provider, :openid)
      }
    end
  end

  defp provider_url(provider, type) do
    "#{Bonfire.Common.URIs.base_url()}/#{type}/client/#{provider}"
  end

  def link_provider_token(current_user, provider, provider_token) do
    case Bonfire.Common.Cache.get(provider_token) do
      {:ok, %{} = provider_params} ->
        link_provider_alias(current_user, provider, provider_config(provider), provider_params)

        Bonfire.Common.Cache.remove(provider_token)

      other ->
        err(other, "No data for token #{inspect(provider_token)}")
        :ok
    end
  end

  def link_provider_alias(current_user, provider, provider_config, params) do
    user_external_url(params, provider_config)
    ~> Utils.maybe_apply(Bonfire.Social.Graph.Aliases, :add, [
      current_user,
      {:provider, provider, provider_config[:display_name], ..., params},
      [update_existing: true]
    ])
  end

  def user_external_url(%{"html_url" => url} = _params, _provider_config)
      when is_binary(url) do
    {:ok, url}
  end

  def user_external_url(%{"url" => url} = _params, _provider)
      when is_binary(url) do
    {:ok, url}
  end

  def user_external_url(%{"iss" => base_url, "sub" => external_id} = _params, _provider)
      when is_binary(base_url) and is_binary(external_id) do
    #  support ORCID.org
    {:ok, "#{base_url}/#{external_id}"}
  end

  def user_external_url(params, provider_config)
      when is_map(provider_config) or is_list(provider_config) do
    case provider_config[:profile_url_pattern] do
      nil ->
        fallback_external_url(params, provider_config)

      pattern ->
        # Find all placeholders in the pattern
        placeholders =
          Regex.scan(~r/{([^}]+)}/, pattern, capture: :all_but_first)
          |> Enum.map(&List.first/1)

        # Check if any placeholders are present and non-empty in params
        if Enum.any?(placeholders, fn key ->
             value = Map.get(params, key)
             is_binary(value) and value != ""
           end) do
          replaced =
            Regex.replace(~r/{([^}]+)}/, pattern, fn _, key ->
              URI.encode(to_string(Map.get(params, key)))
            end)

          {:ok, replaced}
        else
          fallback_external_url(params, provider_config)
        end
    end
  end

  defp fallback_external_url(params, provider_config) do
    with id when not is_nil(id) <- Map.get(params, "id") || Map.get(params, "user_id"),
         uri when is_binary(uri) <-
           provider_config[:authorize_uri] || provider_config[:access_token_uri],
         %URI{host: host, scheme: scheme} = URI.parse(uri),
         true <- is_binary(host) and is_binary(scheme) do
      {:ok, "#{scheme}://#{host}#user_id=#{id}"}
    else
      e ->
        warn(e, "Not able to generate fallback url")
        error(params, l("Not able to find the user profile URL in the data provided"))
    end
  end

  def user_external_url(params, _) do
    error(params, l("Not able to find the user profile URL in the data provided"))
  end
end
