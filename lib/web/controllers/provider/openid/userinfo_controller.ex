defmodule Bonfire.OpenID.Web.Openid.UserinfoController do
  @behaviour Boruta.Openid.UserinfoApplication

  use Bonfire.UI.Common.Web, :controller

  alias Boruta.Openid.UserinfoResponse

  alias Bonfire.OpenID.Web.OpenidView

  def openid_module,
    do: Application.get_env(:bonfire_open_id, :openid_module, Boruta.Openid)

  def userinfo(conn, _params) do
    if current_user = current_user(conn) do
      # workaround for checking the userinfo when authenticated in a browser
      with {:ok, resource_owner} <- Bonfire.OpenID.get_user(current_user),
      {:ok, userinfo} <- Boruta.Oauth.Token.userinfo(%Boruta.Oauth.Token{resource_owner: resource_owner, type: :access_token, scope: nil}) |> flood("basic userinfo"), 
      %{} = client <- Bonfire.OpenID.Provider.ClientApps.init_test_client_app() do
        userinfo_fetched(conn, UserinfoResponse.from_userinfo(userinfo, client |> Boruta.Ecto.OauthMapper.to_oauth_schema()) |> flood("from_userinfo"))
      end
    else
      # regular Boruta integration
      openid_module().userinfo(conn, __MODULE__)
    end
    
  end

  @impl Boruta.Openid.UserinfoApplication
  def userinfo_fetched(conn, userinfo_response) do
    flood(userinfo_response, "userinfo_fetched") 
    if userinfo_response.format == :jwt do
        # Send raw JWT with correct content-type, no JSON encoding
        conn
        |> put_resp_content_type("application/jwt")
        |> send_resp(200, userinfo_response.jwt)

    else
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
