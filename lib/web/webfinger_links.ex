defmodule Bonfire.OpenID.Web.WebfingerLinks do
  @moduledoc "Adds this instance's OpenID Connect issuer to each WebFinger answer (OpenID Connect Discovery 1.0, section 2), so a client that knows only someone's handle finds where they sign in. Listed under `webfinger_link_modules` in the `:activity_pub, :instance` config."

  @issuer_rel "http://openid.net/specs/connect/1.0/issuer"

  def gather_webfinger_links(_id) do
    if Bonfire.OpenID.Provider.enabled?() do
      # the same value as the `issuer` of the discovery documents, which a client checks it against
      [%{"rel" => @issuer_rel, "href" => Bonfire.Common.URIs.base_url()}]
    else
      []
    end
  end
end
