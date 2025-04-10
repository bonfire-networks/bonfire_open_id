defmodule Bonfire.OpenID.Web.Controllers.Openid.AuthorizeControllerTest do
  use ExUnit.Case, async: true
  import Plug.Conn
  import Phoenix.ConnTest

  import Mox

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Bonfire.OpenID.Web.Openid.AuthorizeController

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
    defstruct id: 1, email: "test@test.test", last_login_at: nil
  end

  describe "authorize/2" do
    test "redirects_to login if prompt=login", %{conn: conn} do
      conn = %{conn | query_params: %{"prompt" => "login"}}

      assert_authorize_user_logged_out(conn)
    end

    test "redirects_to login if user is invalid", %{conn: conn} do
      current_user = %User{}
      conn = assign(conn, :current_user, current_user)

      error = %Error{
        status: :unauthorized,
        error: :invalid_resource_owner,
        error_description: "Error description",
        format: :query
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_error(conn, error)
      end)

      assert_authorize_redirected_to_login(conn)
    end

    test "redirects_to an error if prompt=none and user not logged in", %{
      conn: conn
    } do
      conn = %{conn | query_params: %{"prompt" => "none"}}

      error = %Error{
        status: :unauthorized,
        error: :login_required,
        error_description: "Error description",
        format: :fragment
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_error(conn, error)
      end)

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

      assert redirected_to(conn) =~ ~r/error=login_required/
    end

    test "redirects to login if user is logged in and max age is expired", %{
      conn: conn
    } do
      current_user = %User{last_login_at: DateTime.utc_now()}
      conn = assign(conn, :current_user, current_user)
      conn = %{conn | query_params: %{"max_age" => "0"}}

      assert_authorize_user_logged_out(conn)
    end

    test "authorizes if user is logged in and max age is not expired", %{
      conn: conn
    } do
      current_user = %User{last_login_at: DateTime.utc_now()}
      conn = assign(conn, :current_user, current_user)
      conn = %{conn | query_params: %{"max_age" => "10"}}

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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

      assert redirected_to(conn) in [
               "http://redirect.uri#access_token=access_token&expires_in=10",
               "http://redirect.uri#expires_in=10&access_token=access_token"
             ]
    end

    test "redirects to user login when user not logged in", %{conn: conn} do
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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

      assert html_response(conn, 400) =~ ~r/Error description/
      # assert html_response(conn, 400) =~ ~r/Request is not a valid/
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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

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

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

      assert redirected_to(conn) ==
               "http://redirect.uri?code=code&state=state"
    end
  end

  defp assert_authorize_redirected_to_login(conn) do
    assert redirected_to(AuthorizeController.authorize(conn, %{"response_type" => "code"})) =~
             "login"
  end

  defp assert_authorize_user_logged_out(conn) do
    assert redirected_to(AuthorizeController.authorize(conn, %{"response_type" => "code"})) =~
             "logout"
  end
end
