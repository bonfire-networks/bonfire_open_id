defmodule Bonfire.OpenID.Web.Controllers.Openid.AuthorizeControllerTest do
  use Bonfire.OpenID.ConnCase, async: true
  import Plug.Conn
  import Phoenix.ConnTest

  import Mox

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  # boruta 3.0: AuthorizeResponse `code`/`access_token` are %Token{} structs (read via `.value`)
  alias Boruta.Oauth.Token
  alias Bonfire.OpenID.Web.Openid.AuthorizeController
  alias Bonfire.UI.Common.Testing.Helpers

  setup :verify_on_exit!

  setup do
    conn =
      init_test_session(
        %{build_conn() | query_params: %{}},
        %{}
      )

    account = Helpers.fake_account!()

    # loaded the way `LoadCurrentUser` loads it for a real request, so the account is already
    # preloaded: `Seen.normalize_subject!/1`, which `get_user/1` reaches for `last_login_at`,
    # flags both a current_user with no account and one whose account it has to go and fetch
    current_user =
      Helpers.fake_user!(account)
      |> then(&Bonfire.UI.Me.LivePlugs.LoadCurrentUser.get_current(&1.id, account.id))

    # These tests mock boruta's `authorize` directly — pre-grant consent for the
    # current_user so the controller skips the consent screen (`preauthorize`) and
    # exercises the mocked `authorize` path.
    Bonfire.OpenID.Web.Consent.remember_consent_all(current_user)

    {:ok, conn: conn, current_user: current_user, account: account}
  end

  describe "authorize/2" do
    test "redirects_to login if prompt=login", %{conn: conn} do
      conn = %{conn | query_params: %{"prompt" => "login"}}

      assert_authorize_user_logged_out(conn)
    end

    test "redirects_to login if user is invalid", %{conn: conn, current_user: current_user} do
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
      conn: conn,
      current_user: current_user
    } do
      # `get_user/1` reads last-login back out of the Seen edge that login writes, so write a real one rather than fabricating the field
      Bonfire.Social.Seen.mark_seen(current_user, current_user, upsert: true)
      conn = assign(conn, :current_user, current_user)
      conn = %{conn | query_params: %{"max_age" => "0"}}

      assert_authorize_user_logged_out(conn)
    end

    test "authorizes if user is logged in and max age is not expired", %{
      conn: conn,
      current_user: current_user
    } do
      # `get_user/1` reads last-login back out of the Seen edge that login writes, so write a real one rather than fabricating the field
      Bonfire.Social.Seen.mark_seen(current_user, current_user, upsert: true)
      conn = assign(conn, :current_user, current_user)
      conn = %{conn | query_params: %{"max_age" => "10"}}

      response = %AuthorizeResponse{
        type: :token,
        redirect_uri: "http://redirect.uri",
        access_token: %Token{type: "access_token", value: "access_token"},
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

    test "returns an error page", %{conn: conn, current_user: current_user} do
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

    test "returns an error in fragment", %{conn: conn, current_user: current_user} do
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

    test "returns an error in query", %{conn: conn, current_user: current_user} do
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

    test "redirects with an access_token", %{conn: conn, current_user: current_user} do
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :token,
        redirect_uri: "http://redirect.uri",
        access_token: %Token{type: "access_token", value: "access_token"},
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

    test "redirects with an access_token and a state", %{conn: conn, current_user: current_user} do
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :token,
        redirect_uri: "http://redirect.uri",
        access_token: %Token{type: "access_token", value: "access_token"},
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

    test "redirects with an code", %{conn: conn, current_user: current_user} do
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :code,
        redirect_uri: "http://redirect.uri",
        code: %Token{type: "code", value: "code"}
      }

      Boruta.OauthMock
      |> expect(:authorize, fn conn, _resource_owner, module ->
        module.authorize_success(conn, response)
      end)

      conn = AuthorizeController.authorize(conn, %{"response_type" => "code"})

      assert redirected_to(conn) ==
               "http://redirect.uri?code=code"
    end

    test "redirects with an code and a state", %{conn: conn, current_user: current_user} do
      conn = assign(conn, :current_user, current_user)

      response = %AuthorizeResponse{
        type: :code,
        redirect_uri: "http://redirect.uri",
        code: %Token{type: "code", value: "code"},
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

    test "authorization requires valid client", %{conn: conn} do
      # Test with invalid client_id directly through conn
      conn = get(conn, "/openid/authorize?client_id=invalid&response_type=code&scope=openid")

      # Should return an error or redirect to error page
      assert conn.status in [400, 302, 404]
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
