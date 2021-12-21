function urlencodeFormData(fd){
    var s = '';
    function encode(s){ return encodeURIComponent(s).replace(/%20/g,'+'); }
    for(var pair of fd.entries()){
        if(typeof pair[1]=='string'){
            s += (s?'&':'') + encode(pair[0])+'='+encode(pair[1]);
        }
    }
    return s;
}

function submitForm()
{
    var formData = urlencodeFormData(new FormData(document.getElementById("form")));
    var xhr = new XMLHttpRequest()

    xhr.open("POST", "/testsite", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function() {
        if (this.readyState === XMLHttpRequest.DONE) {
            document.getElementById("msg").innerHTML = xhr.response;
        }
    }
    xhr.send(formData);

    return false;
}
