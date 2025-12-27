defmodule Bonfire.OpenID.Web.Openid.UserinfoController do
  @behaviour Boruta.Openid.UserinfoApplication

  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Openid.UserinfoResponse

  alias Bonfire.OpenID.Web.OpenidView

  def openid_module,
    do: Application.get_env(:bonfire_open_id, :openid_module, Boruta.Openid)

  def userinfo(conn, _params) do
    openid_module().userinfo(conn, __MODULE__)
  end

  @impl Boruta.Openid.UserinfoApplication
  def userinfo_fetched(conn, userinfo_response) do
    cond do
      userinfo_response.format == :jwt ->
        # Send raw JWT with correct content-type, no JSON encoding
        conn
        |> put_resp_content_type("application/jwt")
        |> send_resp(200, userinfo_response.jwt)

      true ->
        # Fall back to rendering for other formats (e.g., plain JSON)
        conn
        |> put_view(OpenidView)
        |> put_resp_header("content-type", UserinfoResponse.content_type(userinfo_response))
        |> render("userinfo.json", response: userinfo_response)
    end
  end

  @impl Boruta.Openid.UserinfoApplication
  def unauthorized(conn, error) do
    conn
    |> put_resp_header(
      "www-authenticate",
      "error=\"#{error.error}\", error_description=\"#{error.error_description}\""
    )
    |> send_resp(
      :unauthorized,
      error.error_description || "Could not authenticate or find userinfo"
    )
  end

  def openid_discovery(conn, _) do
    conn
    |> put_view(OpenidView)
    |> render("openid-configuration.json")
  end
end
