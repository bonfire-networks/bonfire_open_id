defmodule Bonfire.OpenID.Web.OpenidView do
  use Bonfire.Web, :view

  def render("jwks.json", %{jwk_keys: jwk_keys}) do
    %{keys: jwk_keys}
  end

  def render("userinfo.json", %{userinfo: userinfo}) do
    userinfo
  end

  def render("error.html", %{error: error, error_description: error_description}) do
    error_description
  end
end
