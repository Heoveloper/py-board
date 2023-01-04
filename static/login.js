const id = document.getElementById('id');
const pw = document.getElementById('pw');
const $login = document.querySelector('.login');

function login() {
    const url = `/login`;
    const data = {
        "id": id,
        "pw": pw
    };
    fetch(url, {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then(res => res)
      .then(res => {
        console.log(res)
        console.log(res.body)
        console.log(res.headers)
        if (res.ok == true) {
            alert('로그인 성공!')
        } else {
            alert('로그인 실패ㅠㅠ')
        }
      })
      .catch(err => console.log(err));
}