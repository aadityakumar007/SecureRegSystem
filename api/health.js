// Health check endpoint
module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/json');
    
    res.status(200).json({
        status: 'ok',
        message: 'API is working',
        timestamp: new Date().toISOString()
    });
}; 