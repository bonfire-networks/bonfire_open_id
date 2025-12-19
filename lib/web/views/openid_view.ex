defmodule Bonfire.OpenID.Web.OpenidView do
  use Bonfire.UI.Common.Web, :view

  alias Boruta.Openid.UserinfoResponse

  def render("jwks.json", %{jwk_keys: jwk_keys}) do
    %{keys: jwk_keys}
  end

  def render("userinfo.json", %{response: response}) do
    UserinfoResponse.payload(response)
  end

  def render("openid-configuration.json", _) do
    Bonfire.OpenID.Provider.openid_configuration_data()
  end

  def render("error.html", %{error: error, error_description: error_description}) do
    error(error, to_string(error_description))
    error_description
  end
end
