** env_guide **

PORT=

JWT_KEY=

---------

** api_service **

method            path                 params           body

POST         /auth/register            none             {username, password, email}                               
POST         /auth/login               none             {username, password, }
PUT          /todo                      :id