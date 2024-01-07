import express from 'express';
import mysql from 'mysql';

const app = express();

// MySQL connection configuration
const dbConfig: mysql.ConnectionConfig = {
  host: 'mysql-container', // Use the name of your MySQL container on the Docker network
  user: 'root',
  password: 'my-secret-pw', // Set during MySQL container creation
  database: 'your_database', // Replace with your actual database name
};

// Create a MySQL connection pool
const pool = mysql.createPool(dbConfig);

// Endpoint to handle incoming requests
app.get('/your_endpoint', (req, res) => {

  res.json({legal: "legal"})
  // For example, send a SELECT query to the MySQL container
  pool.query('SELECT * FROM your_table', (error, results, fields) => {
    if (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
      return;
    }

    // Process the MySQL query results
    res.json(results);
  });
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});