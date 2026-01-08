defmodule Bonfire.OpenID.Web.Openid.ClientRegistrationController do
  use Bonfire.UI.Common.Web, :controller

  import Untangle
  alias Bonfire.OpenID.Provider.ClientApps

  def register(conn, params) do
    case ClientApps.register_dynamic_client(params) do
      {:ok, client_data} ->
        conn
        |> put_status(:created)
        |> json(client_data)

      {:error, :invalid_redirect_uri} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          "error" => "invalid_redirect_uri",
          "error_description" => "One or more redirect_uris is invalid"
        })

      {:error, :invalid_client_metadata} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          "error" => "invalid_client_metadata",
          "error_description" => "Invalid client metadata provided"
        })

      {:error, reason} ->
        flood(reason, "Client registration failed")

        conn
        |> put_status(:bad_request)
        |> json(%{
          "error" => "invalid_client_metadata",
          "error_description" => "Client registration failed"
        })
    end
  end

  def retrieve(conn, %{"client_id" => client_id}) do
    with {:ok, registration_token} <- get_registration_token(conn),
         {:ok, client_data} <- ClientApps.get_client_configuration(client_id, registration_token) do
      json(conn, client_data)
    else
      {:error, :invalid_token} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{"error" => "invalid_token"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{"error" => "invalid_client"})
    end
  end

  def update(conn, %{"client_id" => client_id} = params) do
    with {:ok, registration_token} <- get_registration_token(conn),
         {:ok, updated_client} <-
           ClientApps.update_client_configuration(client_id, registration_token, params) do
      json(conn, updated_client)
    else
      {:error, :invalid_token} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{"error" => "invalid_token"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{"error" => "invalid_client"})
    end
  end

  def delete(conn, %{"client_id" => client_id}) do
    with {:ok, registration_token} <- get_registration_token(conn),
         :ok <- ClientApps.delete_client(client_id, registration_token) do
      send_resp(conn, :no_content, "")
    else
      {:error, :invalid_token} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{"error" => "invalid_token"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{"error" => "invalid_client"})
    end
  end

  defp get_registration_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, token}
      _ -> {:error, :invalid_token}
    end
  end
end
