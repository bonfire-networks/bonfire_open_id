defmodule Bonfire.OpenID.Web.Controllers.Oauth.TokenControllerTest do
  use Bonfire.OpenID.ConnCase, async: true
  import Phoenix.ConnTest

  import Mox

  alias Boruta.Oauth.Error
  alias Boruta.Oauth.TokenResponse
  alias Bonfire.OpenID.Web.Oauth.TokenController

  setup :verify_on_exit!

  setup do
    {:ok, conn: build_conn()}
  end

  describe "token/2" do
    test "returns an oauth error", %{conn: conn} do
      error = %Error{
        status: :bad_request,
        error: :unknown_error,
        error_description: "Error description"
      }

      Boruta.OauthMock
      |> expect(:token, fn conn, module ->
        module.token_error(conn, error)
      end)

      conn = TokenController.token(conn, %{})

      assert json_response(conn, 400) == %{
               "error" => "unknown_error",
               "error_description" => "Error description"
             }
    end

    test "returns an oauth response", %{conn: conn} do
      response = %TokenResponse{
        access_token: "access_token",
        expires_in: 10,
        token_type: "token_type",
        refresh_token: "refresh_token"
      }

      Boruta.OauthMock
      |> expect(:token, fn conn, module ->
        module.token_success(conn, response)
      end)

      conn = TokenController.token(conn, %{})

      assert %{
               "access_token" => "access_token",
               "expires_in" => 10,
               "token_type" => "Token_type",
               "refresh_token" => "refresh_token"
             } = json_response(conn, 200)
    end
  end
end
