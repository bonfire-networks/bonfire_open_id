defmodule Bonfire.OpenID.Web.Controllers.Oauth.AuthorizeControllerTest do
  use Bonfire.OpenID.ConnCase, async: true
  import Plug.Conn
  import Phoenix.ConnTest

  import Mox

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Bonfire.OpenID.Web.Oauth.AuthorizeController

  setup :verify_on_exit!

  setup do
    conn =
      init_test_session(
        %{build_conn() | query_params: %{}},
        %{}
      )

    {:ok, conn: conn}
  end

  defmodule User do
    defstruct id: 1, email: "test@test.test"
  end

  describe "authorize/2" do
    test "redirects to user login without current_user", %{conn: conn} do
      assert_authorize_redirected_to_login(conn)
    end

    test "returns an error page", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      error = %Error{
        status: :bad_request,
        error: :unknown_error,
        error_description: "Error description"
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_error(conn, error)
      end)

      conn = AuthorizeController.authorize(conn, %{})

      assert html_response(conn, 400) =~ ~r/Error description/
    end

    test "returns an error in fragment", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      error = %Error{
        status: :bad_request,
        error: :unknown_error,
        error_description: "Error description",
        format: :fragment,
        redirect_uri: "http://redirect.uri"
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_error(conn, error)
      end)

      conn = AuthorizeController.authorize(conn, %{})

      assert redirected_to(conn) ==
               "http://redirect.uri#error=unknown_error&error_description=Error+description"
    end

    test "returns an error in query", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      error = %Error{
        status: :bad_request,
        error: :unknown_error,
        error_description: "Error description",
        format: :query,
        redirect_uri: "http://redirect.uri"
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_error(conn, error)
      end)

      conn = AuthorizeController.authorize(conn, %{})

      assert redirected_to(conn) ==
               "http://redirect.uri?error=unknown_error&error_description=Error+description"
    end

    test "redirects with an access_token", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :token,
        redirect_uri: "http://redirect.uri",
        access_token: "access_token",
        expires_in: 10
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_success(conn, response)
      end)

      conn = AuthorizeController.authorize(conn, %{})

      assert redirected_to(conn) in [
               "http://redirect.uri#access_token=access_token&expires_in=10",
               "http://redirect.uri#expires_in=10&access_token=access_token"
             ]
    end

    test "redirects with an access_token and a state", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :token,
        redirect_uri: "http://redirect.uri",
        access_token: "access_token",
        expires_in: 10,
        state: "state"
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_success(conn, response)
      end)

      conn = AuthorizeController.authorize(conn, %{})

      assert redirected_to(conn) in [
               "http://redirect.uri#access_token=access_token&expires_in=10&state=state",
               "http://redirect.uri#state=state&expires_in=10&access_token=access_token",
               "http://redirect.uri#state=state&access_token=access_token&expires_in=10"
             ]
    end

    test "redirects with an code", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :code,
        redirect_uri: "http://redirect.uri",
        code: "code"
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_success(conn, response)
      end)

      conn = AuthorizeController.authorize(conn, %{})

      assert redirected_to(conn) ==
               "http://redirect.uri?code=code"
    end

    test "redirects with an code and a state", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :code,
        redirect_uri: "http://redirect.uri",
        code: "code",
        state: "state"
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_success(conn, response)
      end)

      conn = AuthorizeController.authorize(conn, %{})

      assert redirected_to(conn) ==
               "http://redirect.uri?code=code&state=state"
    end
  end

  defp assert_authorize_redirected_to_login(conn) do
    assert redirected_to(AuthorizeController.authorize(conn, %{})) =~ "login"
  end
end
