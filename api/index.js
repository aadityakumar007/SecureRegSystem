module.exports = (req, res) => {
    res.json({ 
        success: true,
        csrfToken: 'test-token-' + Date.now()
    });
}; 