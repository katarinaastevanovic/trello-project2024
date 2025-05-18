const cassandra = require('cassandra-driver');

// Konekcija sa Cassandra bazom
const client = new cassandra.Client({
  contactPoints: ['127.0.0.1'], // IP adresa Cassandra servera
  localDataCenter: 'datacenter1', // Ime Data Centra (proveri u konfiguraciji Cassandre)
  keyspace: 'notifications' // Keyspace koji koristiš
});

async function testConnection() {
  try {
    // Test konekcije
    await client.connect();
    console.log('Connected to Cassandra!');
    
    // Testni upit
    const result = await client.execute('SELECT * FROM notifications');
    console.log('Rows:', result.rows);
    
  } catch (error) {
    console.error('Failed to connect to Cassandra:', error);
  } finally {
    // Zatvaranje konekcije
    await client.shutdown();
  }
}

testConnection();
