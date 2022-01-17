var express = require("express");
var createcon = require('./custom_modules/modconnection');
var tempCont = new createcon();
var path = require("path");
var fs = require("fs");
var m = require('mysql');
var bodyParser = require('body-parser');
var sessions = require('express-session');
var flash = require('express-flash');
var cookieParser = require('cookie-parser');
// var dateFormat = require('dateformat');
var app = express();
var csrf = require('csurf');
var country = fs.readFileSync("country.json");
var countrybuf_tostring = JSON.parse(country);
var nodemailer = require('nodemailer');
var nodeExcel = require('excel-export');
var bcrypt = require('bcrypt');
// var randomstring = require("randomstring");
var saltRounds = 15;
var xss = require("xss")
// npm install --save-dev express path fs mysql body-parser express-session express-flash cookie-parser dateformat csurf nodemailer excel-export bcrypt xss ejs

/**Setup**/
app.use("/css", express.static(__dirname + "/webpage/stylecss"));
app.use("/js", express.static(__dirname + "/webpage/jsscript"));
app.use("/font", express.static(__dirname + "/webpage/font"));
app.use("/images", express.static(__dirname + "/webpage/images"));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname,"/webpage"));
app.use(sessions({
    secret: "bMebTAWEwIwfBijHkSAmEozIpKpDvGyXRqUwbjbL",
    resave: true,
    saveUninitialized: true
}));
app.use(flash());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:false}));
app.use(cookieParser());
app.use(csrf({ cookie: true }));
/**End Setup**/

var transporter = nodemailer.createTransport({
    //host: 'smtp.mailtrap.io',
    //port: 2525,
    //secure: false,
    //auth: {
    //    user: '266201e095ce7f',
    //    pass: '257992be384261'
    //}
});


app.get('/', function(req, res, next) {
    session = req.session;
    res.render('index',
        {
            'title': 'Jack Frost - Coming Soon!!',
            'csrfToken': req.csrfToken()
        }
    );
});


app.get('/testsite', function(req, res, next) {
    session = req.session;
    res.render('testsite',
        {
            'title': 'Frost Tower --- Test Site',
        }
    );
});


app.post('/testsite', function(req, res, next){
    var email = xss(req.body.email);

    tempCont.query("SELECT * FROM emails WHERE email="+tempCont.escape(email), function(error, rows, fields){
        if (error) {
            console.log(error);
            return res.sendStatus(500);
        }

        var rowlength = rows.length;
        if (rowlength >= "1"){
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.write("Email already saved");
            return res.end();
        }else{
            tempCont.query("INSERT INTO emails (email) VALUE ("+tempCont.escape(email)+")", function(error, rows, fields){
                if (error) {
                    console.log(error);
                    return res.sendStatus(500);
                }

                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.write("Thank you!");
                return res.end();
            });
        }}
    );
});




app.get('/contact', function(req, res, next){
    session = req.session;
    tempCont.query("SELECT * from uniquecontact order by date_created desc", function(error, rows, fields){
        if (error) {
            return res.sendStatus(500);
        }

        var rowdata = rows.length;

        res.render('contact',
            {
                'title': 'Contact Us',
                'strcountry': countrybuf_tostring,
                'rowdata': rowdata,
                'csrfToken': req.csrfToken(),
                'userlogin': session.userfullname
            }
        );

    });
});

app.post('/postcontact', function(req, res, next){
    var fullname = xss( ReplaceAnyMatchingWords(req.body.fullname) );
    var email = xss( ReplaceAnyMatchingWords( req.body.email) );
    var phone = xss( ReplaceAnyMatchingWords( req.body.phone) );
    var country = xss( ReplaceAnyMatchingWords( req.body.country ) );
    var date = new Date();
    var d = date.getDate();
    var mo = date.getMonth();
    var yr = date.getFullYear();
    var current_hour = date.getHours();
    var date_created = data;
    // dateFormat(date, "yyyy-mm-dd hh:MM:ss");

    tempCont.query("SELECT * from uniquecontact where email="+tempCont.escape(email), function(error, rows, fields){

        if (error) {
            console.log(error);
            return res.sendStatus(500);
        }

        var rowlength = rows.length;
        if (rowlength >= "1"){
            session = req.session;
            session.uniqueID = email;
            req.flash('info', 'Email Already Exists');
            res.redirect("/contact");

        } else {

            tempCont.query("INSERT INTO uniquecontact (full_name, email, phone, country, date_created) VALUE (?, ?, ?, ?, ?)", [fullname, email, phone, country, date_created], function(error, rows, fields) {

                if (error) {
                    console.log(error);
                    return res.sendStatus(500);
                }

                res.render('email/e_template_1', { name: fullname }, function (err, data) {

                    // setup email data with unicode symbols
                    var mailOptions = {
                        from: 'Admin <admin@localhost>',
                        to: email,
                        subject: 'Thank you for contacting us!',
                        html: data
                    };

                    //  // send mail with defined transport object
                    //  transporter.sendMail(mailOptions, (error, info) => {
                    //      if (error) {
                    //          return console.log(error);
                    //      }
                    //      console.log('Message sent: %s', info.messageId);
                    //  });

                    session = req.session;
                    req.flash('info', 'Data Saved to Database!');
                    res.redirect("/contact");

                });

            });

        }

    });
});

app.get('/detail/:id', function(req, res, next) {
    session = req.session;
    var reqparam = req.params['id'];
    var query = "SELECT * FROM uniquecontact WHERE id=";

    if (session.uniqueID){

        try {
            if (reqparam.indexOf(',') > 0){
                var ids = reqparam.split(',');
                reqparam = "0";
                for (var i=0; i<ids.length; i++){
                    query += tempCont.escape(m.raw(ids[i]));
                    query += " OR id="
                }
                query += "?";
            }else{
                query = "SELECT * FROM uniquecontact WHERE id=?"
            }
        } catch (error) {
            console.log(error);
            return res.sendStatus(500);
        }

        tempCont.query(query, reqparam, function(error, rows, fields){

            if (error) {
                console.log(error);
                return res.sendStatus(500);
            }

            var rowdata = rows.length;

            if (rowdata == 0){
                res.render('404',
                    {
                        'title': 'Not found!',
                        'userlogin': session.userfullname
                    }
                );
            }else{
                res.render('detail',
                    {
                        'title': 'Detail Contact',
                        'encontact': rows,
                        'dateFormat': dateFormat,
                        'csrfToken': req.csrfToken(),
                        'userlogin': session.userfullname,
                        'userstatus': session.userstatus
                    }
                );
            }
        });
    }else{
        res.redirect("/login");
    }
});

app.get('/edit/:id', function(req, res, next) {
    session = req.session;
    var reqparam = req.params['id'];

    if (session.uniqueID){

        tempCont.query("SELECT * from uniquecontact where id=" + tempCont.escape(reqparam), function(error, rows, fields){

            if (error) {
                console.log(error);
                return res.sendStatus(500);
            }

            var rowdata = rows.length;

            if (rowdata == 0){
                res.render('404',
                    {
                        'title': 'Not found!',
                        'userlogin': session.userfullname
                    }
                );
            }else{
                res.render('edit',
                    {
                        'title': 'Edit Form Contact',
                        'strcountry': countrybuf_tostring,
                        'encontact': rows,
                        'csrfToken': req.csrfToken(),
                        'userlogin': session.userfullname
                    }
                );
            }

        });

    }else{
        res.redirect("/login");
    }

});

app.post('/edit/:id', function(req, res, next){
    session = req.session;

    if (session.uniqueID){

        var reqid = xss(req.params['id']);
        var fullname = xss(req.body.fullname);
        var phone = xss(req.body.phone);
        var country = xss(req.body.country);
        var date = new Date();
        var d = date.getDate();
        var mo = date.getMonth();
        var yr = date.getFullYear();
        var current_hour = date.getHours();
        var date_update = dateFormat(date, "yyyy-mm-dd hh:MM:ss");


        tempCont.query("UPDATE uniquecontact SET full_name=?, phone=?, country=?, date_update=? WHERE id=?", [fullname, phone, country, date_update, reqid], function(error, rows, fields){

            if (error) {
                console.log(error);
                return res.sendStatus(500);
            }

            session = req.session;
            session.uniqueID = fullname;
            req.flash('info', 'Data Updated!');
            res.redirect("/dashboard");
        });


    }else{
        res.redirect("/login");
    }
});

app.post('/delete/:id', function(req, res, next){
    session = req.session;

    if (session.uniqueID){

        if (session.userstatus == 1){

            var reqid = req.params['id'];

            tempCont.query("DELETE from uniquecontact WHERE id=?", reqid, function(error, rows, fields){

                if (error) {
                    console.log(error);
                    return res.sendStatus(500);
                }

                session = req.session;
                session.uniqueID = reqid;
                req.flash('info', 'Success deleted record!');
                res.redirect("/dashboard");
            });

        }else{
            res.send('Authorization error');
        }

    }else{
        res.redirect("/login");
    }
});

app.get('/search', function(req, res, next) {
    session = req.session;

    if (session.uniqueID){

        var search = req.query.key;
        search = "%" + search + "%"

        tempCont.query("SELECT * from uniquecontact WHERE full_name like "+tempCont.escape(search)+" OR email like "+tempCont.escape(search)+" OR phone like "+tempCont.escape(search)+" order by id desc", function(error, rows, fields){

            if (error) {
                console.log(error);
                res.sendStatus(500);
            }

            var rowdata = rows.length;

            //set default variables
            var totalRecord = rowdata,
                pageSize = 10,
                pageCount = Math.ceil(rowdata/10),
                currentPage = 1,
                encontact = rows,
                encontactArrays = [],
                encontactList = [];
            //split list into groups
            while (encontact.length) {
                encontactArrays.push(encontact.splice(0, pageSize));
            }

            //set current page if specifed as get variable (eg: /?page=2)
            if (typeof req.query.page !== 'undefined' && req.query.page == parseInt(req.query.page, 10)) {
                if (req.query.page <= encontactArrays.length) {
                    currentPage = +req.query.page;
                }
            }

            //show list of encontact from group
            encontactList = encontactArrays[+currentPage - 1];
            //render index.ejs view file

            if ( rowdata == "0"){

                res.render('404',
                    {
                        'title': 'Record Not Found!',
                        'userlogin': session.userfullname
                    }

                );
            }else{

                res.render('search',
                    {
                        'title': 'Form Contact',
                        'strcountry': countrybuf_tostring,
                        'encontact': encontactList,
                        'pageSize': pageSize,
                        'totalRecord': totalRecord,
                        'pageCount': pageCount,
                        'currentPage': currentPage,
                        'dateFormat': dateFormat,
                        'csrfToken': req.csrfToken(),
                        'csrfTokenSearch': req.csrfToken(),
                        'key': search,
                        'userlogin': session.userfullname
                    }
                );

            }

        });

    }else{
        res.redirect("/login");
    }

});

app.post('/search', function(req, res, next) {
    session = req.session;

    if (session.uniqueID){

        var search = req.body.search;
        search = "%" + search + "%"

        tempCont.query("SELECT * from uniquecontact WHERE full_name like "+tempCont.escape(search)+" OR email like "+tempCont.escape(search)+" OR phone like "+tempCont.escape(search)+" order by id desc", function(error, rows, fields){

            if (error) {
                return res.sendStatus(500);
            };

            var rowdata = rows.length;

            //set default variables
            var totalRecord = rowdata,
                pageSize = 10,
                pageCount = Math.ceil(rowdata/10),
                currentPage = 1,
                encontact = rows,
                encontactArrays = [],
                encontactList = [];
            //split list into groups
            while (encontact.length) {
                encontactArrays.push(encontact.splice(0, pageSize));
            }

            //set current page if specifed as get variable (eg: /?page=2)
            if (typeof req.query.page !== 'undefined' && req.query.page == parseInt(req.query.page, 10)) {
                if (req.query.page <= encontactArrays.length) {
                    currentPage = +req.query.page;
                }
            }

            //show list of encontact from group
            encontactList = encontactArrays[+currentPage - 1];
            //render index.ejs view file

            if ( rowdata == "0"){

                res.render('404',
                    {
                        'title': 'Record Not Found!',
                        'userlogin': session.userfullname
                    }

                );
            }else{

                res.render('search',
                    {
                        'title': 'Form Contact',
                        'strcountry': countrybuf_tostring,
                        'encontact': encontactList,
                        'pageSize': pageSize,
                        'totalRecord': totalRecord,
                        'pageCount': pageCount,
                        'currentPage': currentPage,
                        'dateFormat': dateFormat,
                        'csrfToken': req.csrfToken(),
                        'csrfTokenSearch': req.csrfToken(),
                        'key': search,
                        'userlogin': session.userfullname
                    }
                );

            }

        });

    }else{
        res.redirect("/login");
    }

});


app.post('/export', function(req, res, next){
    session = req.session;

    if (session.uniqueID){

        var conf={}
        conf.cols=[
            {
                caption:'ID.',
                type:'number',
                width:100
            },
            {
                caption:'NAME',
                type:'string',
                width:50
            },
            {
                caption:'EMAIL',
                type:'string',
                width:200
            },
            {
                caption:'PHONE',
                type:'string',
                width:200
            },
            {
                caption:'COUNTRY',
                type:'string',
                width:200
            },
            {
                caption:'DATE CREATED',
                type:'string',
                width:200
            },
            {
                caption:'DATE UPDATED',
                type:'string',
                width:200
            }
        ];


        tempCont.query("SELECT * from uniquecontact order by id desc", function(error, rows, fields){

            if (error) {
                return res.sendStatus(500);
            }

            arr=[];
            for(i=0;i<rows.length;i++){

                id=rows[i].id;
                name=rows[i].full_name;
                email=rows[i].email;
                phone=rows[i].phone;
                country=rows[i].country;
                date_created=dateFormat(rows[i].date_created, "dd/mm/yyyy");
                date_update=dateFormat(rows[i].date_update, "dd/mm/yyyy");

                a=[id,name,email, phone, country, date_created, date_update];
                arr.push(a);
            }
            conf.rows=arr;

            var result=nodeExcel.execute(conf);
            res.setHeader('Content-Type','application/vnd.openxmlformates');
            res.setHeader("Content-Disposition","attachment;filename="+"export-encontact.xlsx");
            res.end(result,'binary');

        });
    }else{
        res.redirect("/login");
    }

});


app.get('/login', function(req, res){

            res.render('login',
                {
                'title': 'Sign In',
                'csrfToken': req.csrfToken()
                }
            );
});

app.post('/login', function(req, res, next){

    session = req.session;

    var username = req.body.username;
    var password = req.body.password;

    tempCont.query("SELECT * from users where email="+tempCont.escape(username), function(error, rows, fields){

        if (error) {
            return res.sendStatus(500);
        }

        var rowlength = rows.length;

        if (rowlength >= "1"){

            rows.forEach(function(item){

                var q = bcrypt.compareSync(password, item.password);

                if (q == true){
                    session.uniqueID = req.body.username;
                    session.userfullname = rows['0']['name'];
                    session.userstatus = rows['0']['user_status'];
                    res.redirect('/redirect');
                }else{
                    res.redirect('/redirect');
                }

            });

        }else{
            req.session.destroy(function(){
                res.redirect('/redirect');
            });
        }

    });
});

app.get('/redirect', function(req, res){
    session = req.session;

    if (session.uniqueID){
        res.redirect('/dashboard');
    } else {
        req.flash('info', 'Invalid Username or Password');
        res.redirect('/login');
    }
});

app.get('/logout', function(req, res){
    req.session.destroy(function(){
        res.redirect("/contact");
    });
});

app.get('/dashboard', function(req, res, next){

    session = req.session;

    if (session.uniqueID){

        tempCont.query("SELECT * from uniquecontact order by date_created desc", function(error, rows, fields){

            if (error) {
                return res.sendStatus(500);
            }

            var rowdata = rows.length;

            //set default variables
            var totalRecord = rowdata,
                pageSize = 10,
                pageCount = Math.ceil(rowdata/10),
                currentPage = 1,
                encontact = rows,
                encontactArrays = [],
                encontactList = [];
            //split list into groups
            while (encontact.length) {
                encontactArrays.push(encontact.splice(0, pageSize));
            }

            //set current page if specifed as get variable (eg: /?page=2)
            if (typeof req.query.page !== 'undefined' && req.query.page == parseInt(req.query.page, 10)) {
                if (req.query.page <= encontactArrays.length) {
                    currentPage = +req.query.page;
                }
            }

            //show list of encontact from group
            encontactList = encontactArrays[+currentPage - 1];
            //render index.ejs view file

            res.render('dashboard',
                {
                    'title': 'Admin Dashboard',
                    'strcountry': countrybuf_tostring,
                    'encontact': encontactList,
                    'pageSize': pageSize,
                    'totalRecord': totalRecord,
                    'pageCount': pageCount,
                    'currentPage': currentPage,
                    'dateFormat': dateFormat,
                    'csrfToken': req.csrfToken(),
                    'csrfTokenSearch': req.csrfToken(),
                    'csrfTokenExport': req.csrfToken(),
                    'userlogin': session.userfullname,
                    'userstatus': session.userstatus
                }
            );
        });

    } else {
        res.redirect("/login");
    }
});

app.get('/adduser', function(req, res, next){

    session = req.session;

    if (session.uniqueID){

        if (session.userstatus == 1){

            tempCont.query("SELECT * from users order by date_created desc", function(error, rows, fields){
                if (error) {
                    return res.sendStatus(500);
                }

                var rowdata = rows.length;

                res.render('adduser',
                    {
                        'title': 'Add User',
                        'rowdata': rowdata,
                        'csrfToken': req.csrfToken(),
                        'userlogin': session.userfullname
                    }
                );

            });

        }else{
            res.redirect("/dashboard");
        }

    }else{
        res.redirect("/login");
    }
});


app.post('/adduser', function(req, res, next) {

    session = req.session;

    if (session.uniqueID){

        if (session.userstatus == 1){

            var fullname = xss(req.body.fullname);
            var email = xss(req.body.email);
            var saltRounds = 10;
            var password = req.body.password;
            var password = req.body.password;
            var user_status = xss(req.body.user_status);
            var date = new Date();
            var d = date.getDate();
            var mo = date.getMonth();
            var yr = date.getFullYear();
            var current_hour = date.getHours();
            var date_created = dateFormat(date, "yyyy-mm-dd hh:MM:ss");
            var query = "SELECT * from users where email="



            tempCont.query(query + "?", email, function(error, rows, fields){
                if (error) {
                    return res.sendStatus(500);
                }

                var rowlength = rows.length;

                if (rowlength >= "1"){

                    req.flash('info', 'Email Address Already Exists');
                    res.redirect("/adduser");

                } else {

                    bcrypt.hash(password, saltRounds, function(err, hash) {

                        tempCont.query("INSERT INTO users (name, email, password, user_status, date_created) VALUE (?, ?, ?, ?, ?)", [fullname, email, hash, user_status, date_created], function(error, rows, fields){
                            if (error) {
                                return res.sendStatus(500);
                            }

                            req.flash('info', 'User Saved to Database');
                            res.redirect("/adduser");

                        });

                    });

                }

            });

        } else {
            res.redirect("/dashboard");
        }

    } else {
        res.redirect("/login");
    }
});

app.get('/userlist', function(req, res, next){

    session = req.session;

    if (session.uniqueID){

        if (session.userstatus == 1){

            tempCont.query("SELECT * from users order by date_created desc", function(error, rows, fields){

                if (error) {
                    return res.sendStatus(500);
                }

                try {

                    var rowdata = rows.length;

                    //set default variables
                    var totalRecord = rowdata,
                        pageSize = 10,
                        pageCount = Math.ceil(rowdata/10),
                        currentPage = 1,
                        encontact = rows,
                        encontactArrays = [],
                        encontactList = [];
                    //split list into groups
                    while (encontact.length) {
                        encontactArrays.push(encontact.splice(0, pageSize));
                    }

                    //set current page if specifed as get variable (eg: /?page=2)
                    if (typeof req.query.page !== 'undefined' && req.query.page == parseInt(req.query.page, 10)) {
                        if (req.query.page <= encontactArrays.length) {
                            currentPage = +req.query.page;
                        }
                    }

                    //show list of encontact from group
                    encontactList = encontactArrays[+currentPage - 1];
                    //render index.ejs view file

                    res.render('userlist',
                        {
                            'title': 'User Management',
                            'encontact': encontactList,
                            'pageSize': pageSize,
                            'totalRecord': totalRecord,
                            'pageCount': pageCount,
                            'currentPage': currentPage,
                            'dateFormat': dateFormat,
                            'csrfToken': req.csrfToken(),
                            'csrfTokenSearch': req.csrfToken(),
                            'csrfTokenExport': req.csrfToken(),
                            'userlogin': session.userfullname,
                            'userstatus': session.userstatus
                        }
                    );
                } catch (error) {
                    return res.sendStatus(500);
                }

            });

        }else{
            res.redirect("/dashboard");
        }

    }else{
        res.redirect("/login");
    }

});

app.get('/useredit/:id', function(req, res, next) {
    session = req.session;
    var reqparam = req.params['id'];

    if (session.uniqueID){

        if (session.userstatus == 1){

            tempCont.query("SELECT * from users where id=?", reqparam, function(error, rows, fields){

                if (error) {
                    return res.sendStatus(500);
                }

                try {

                    var rowdata = rows.length;

                    if (rowdata == 0){
                        res.render('404',
                            {
                                'title': 'Not found!',
                                'userlogin': session.userfullname
                            }
                        );
                    }else{

                        if (rows['0']['email'] == session.uniqueID){

                            res.render('edituser',
                                {
                                    'title': 'Edit User',
                                    'encontact': rows,
                                    'csrfToken': req.csrfToken(),
                                    'userlogin': session.userfullname,
                                    'userstatus': session.userstatus
                                }
                            );

                        } else {

                            if (rows['0']['user_status'] == session.userstatus){

                                res.redirect('/userlist');

                            }else{

                                res.render('edituser',
                                    {
                                        'title': 'Edit User',
                                        'encontact': rows,
                                        'csrfToken': req.csrfToken(),
                                        'userlogin': session.userfullname,
                                        'userstatus': session.userstatus
                                    }
                                );

                            }

                        }


                    }
                } catch (error) {
                    return res.sendStatus(500);
                }

            });

        }else{
            res.redirect("/dashboard");
        }

    }else{
        res.redirect("/login");
    }

});

app.post('/useredit/:id', function(req, res, next) {
    session = req.session;
    var reqparam = req.params['id'];

    if (session.uniqueID){

        if (session.userstatus == 1){

            var reqid = xss(req.params['id']);
            var name = xss(req.body.fullname);
            var email = xss(req.body.email);
            var user_status = xss(req.body.user_status);
            var password = req.body.password;
            var repassword = req.body.repassword;
            var saltRounds = 10;

            if (password == ""){

                tempCont.query("UPDATE users SET name=?, user_status=? WHERE id=?", [name, user_status, id], function(error, rows, fields){

                    if (error) {
                        return res.sendStatus(500);
                    }

                    session = req.session;
                    session.uniqueID = name;
                    req.flash('info', 'User Updated!');
                    res.redirect("/userlist");
                });

            }else{

                if (password == repassword){

                    bcrypt.hash(password, saltRounds, function(err, hash) {
                        if (err) {
                            return res.sendStatus(500);
                        }

                        tempCont.query("UPDATE users SET name=?, user_status=?, password=? WHERE id=?", [name, user_status, hash, reqid], function(error, rows, fields){

                            if (error) {
                                return res.sendStatus(500);
                            }

                            session = req.session;
                            session.uniqueID = name;
                            req.flash('info', 'User Updated!');
                            res.redirect("/userlist");
                        });

                    });

                }else{
                    req.flash('info', 'Password did not match');
                    res.redirect("/edituser/"+reqid);
                }

            }

        }else{
            res.redirect("/dashboard");
        }

    }else{
        res.redirect("/login");
    }

});

app.post('/userdelete/:id', function(req, res, next){
    session = req.session;

    if (session.uniqueID){

        if (session.userstatus == 1){

            var reqid = req.params['id'];

            tempCont.query("DELETE from users WHERE id=?", reqid, function(error, rows, fields){

                if (error) {
                    return res.sendStatus(500);
                }

                session = req.session;
                session.uniqueID = reqid;
                req.flash('info', 'Success deleted record!');
                res.redirect("/userlist");
            });

        }else{
            res.redirect("/dashboard");
        }

    }else{
        res.redirect("/login");
    }
});

app.get('/forgotpass', function(req, res){

    res.render('forgotpass',
        {
            'title': 'Reset Password',
            'csrfToken': req.csrfToken()
        }
    );

});

app.post('/forgotpass', function(req, res, next){

    var email = req.body.email;
    var fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
    var token = "Ashwin"; 

    // var token = randomstring.generate(); 

    if (email != ""){

        tempCont.query("SELECT * from users WHERE email="+tempCont.escape(email), function(error, rows, fields){

            if (error) {
                return res.sendStatus(500);
            }

            try {

                var checkuser = rows.length;

                if (checkuser >= 1){


                    tempCont.query("UPDATE users SET token=? WHERE email = ?", [token, email], function(error, rows, fields){
                        if (error) {
                            return res.sendStatus(500);
                        }

                        res.render('email/e_template_reset', { email: email, fullUrl: fullUrl, hash: token }, function (err, data) {

                            // setup email data with unicode symbols
                            var mailOptions = {
                                from: 'Admin <foo@nodedev.com>',
                                to: email,
                                subject: 'Encontact Reset Password',
                                html: data
                            };

                            // send mail with defined transport object
                            //transporter.sendMail(mailOptions, (error, info) => {
                            //    if (error) {
                            //        return console.log(error);
                            //    }
                            //    console.log('Message sent: %s', info.messageId);
                            //});

                            req.flash('info', "We've sent reset instruction to your inbox!");
                            res.redirect("/login");

                        });



                    });


                }else{

                    req.flash('info', 'Email not found!');
                    res.redirect("/login");

                }
            } catch (error) {
                return res.sendStatus(500);
            }

        });

    }else{
        res.redirect("/login");
    }

});


app.get('/forgotpass/token/:id', function(req, res, next) {

    var reqparam = req.params['id'];

    if (reqparam != ""){

        tempCont.query("SELECT * from users where token=?", reqparam, function(error, rows, fields){
            if (error) {
                return res.sendStatus(500);
            }


            var rowdata = rows.length;

            if (rowdata == 0){
                res.redirect("/login");

            }else{

                res.render('resetpass',
                    {
                        'title': 'Reset Password',
                        'token': reqparam,
                        'email': rows['0']['email'],
                        'csrfToken': req.csrfToken()
                    }
                );

            }

        });
    }else{
        res.redirect("/login");
    }

});

app.post('/forgotpass/token/:id', function(req, res, next) {

    var password = req.body.password;
    var repassword = req.body.repassword;
    var posttoken = req.body.token;
    var email = req.body.email;

    var reqparam = req.params['id'];

//    if (reqparam != "") {
//        req.flash('info', 'Unable to reset password at this time');
//        res.redirect("/login");
//    }

    if (reqparam != ""){


        tempCont.query("SELECT * from users where token=?", reqparam, function(error, rows, fields){

            if (error) {
                return res.sendStatus(500);
            }

            var rowdata = rows.length;

            if (rowdata == 0){

                res.redirect("/login");

            }else{

                bcrypt.hash(password, saltRounds, function(err, hash) {

                    tempCont.query("UPDATE users SET password=? WHERE token = ?", [hash, posttoken], function(error, rows, fields){

                        tempCont.query("UPDATE users SET token='' where email=?", email, function(error, rows, fields){});

                        req.flash('info', 'Your password has been updated');
                        res.redirect("/login");

                    });

                });

            }

        });

    }else{
        res.redirect("/login");
    }

});

app.listen("1155", function(req, res){
    console.log("Server listening on port 1155");
});
