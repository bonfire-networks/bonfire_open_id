# defmodule Bonfire.OpenID.Application do
#   use Application
#   use Supervisor

#   def start(_type, _args) do
#     children = [
#       worker(OpenIDConnect.Worker, [
#         Bonfire.OpenID.Client.open_id_connect_providers()
#       ])
#     ]

#     opts = [strategy: :one_for_one, name: Bonfire.OpenID.Supervisor, restart: :temporary]
#     Supervisor.start_link(children, opts)
#   end
# end
