const fs = require('fs');
const html = fs.readFileSync('public/index.html', 'utf8');
const script = html.split('<script type="text/babel">')[1].split('</script>')[0];
fs.writeFileSync('test.jsx', script);
