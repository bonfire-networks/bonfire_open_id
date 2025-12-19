defmodule Bonfire.OpenID.Web.Openid.UserinfoController do
  @behaviour Boruta.Openid.UserinfoApplication
  use Bonfire.UI.Common.Web, :controller

  alias Bonfire.OpenID.Web.OpenidView

  def openid_module,
    do: Application.get_env(:bonfire_open_id, :openid_module, Boruta.Openid)

  def userinfo(conn, _params) do
    flood("userinfo called")
    openid_module().userinfo(conn, __MODULE__)
  end

  @impl Boruta.Openid.UserinfoApplication
  def userinfo_fetched(conn, %{userinfo: userinfo}), do: userinfo_fetched(conn, userinfo)

  def userinfo_fetched(conn, userinfo) do
    conn
    |> put_view(OpenidView)
    # TODO: add email address, username, etc?
    |> render("userinfo.json", userinfo: userinfo)
  end

  @impl Boruta.Openid.UserinfoApplication
  def unauthorized(conn, error) do
    conn
    |> put_resp_header(
      "www-authenticate",
      "error=\"#{error.error}\", error_description=\"#{error.error_description}\""
    )
    |> send_resp(:unauthorized, "Could not find userinfo")
  end

  def openid_discovery(conn, _) do
    conn
    |> put_view(OpenidView)
    |> render("openid-configuration.json")
  end
end
