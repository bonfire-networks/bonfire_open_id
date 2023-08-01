defmodule Bonfire.OpenID.OpenIDConnect do

def providers, do: Application.get_env(:bonfire_open_id, :openid_connect_providers, [])

def providers_authorization_urls do
    for {provider, config} < providers do
        OpenIDConnect.authorization_uri(provider)
    end
end

end