Implemented a To-do list in Golang.
Users can register in the system.
After registration, users can log in using their username and password.
Upon successful login, a token is generated.
With the generated token, users can perform various actions:
  Create tasks
  Get tasks
  Delete tasks
  Update tasks
Utilized Postman API calls for these actions.
Data is stored in a PostgreSQL database.
Implemented user-specific access control:
Users can only retrieve tasks they have added.
Users can only delete tasks they have added.
Users can only update tasks they have added.
