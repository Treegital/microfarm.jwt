import pytest
from freezegun import freeze_time


@pytest.mark.asyncio
async def test_generate_token(jwt_service, jwt_client):
    with freeze_time("2023-03-25 12:00:00"):
        response = await jwt_client.get_token({"data": "whatever"})
    assert response == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoid2hhdGV2ZXIiLCJleHAiOjE2Nzk3NDkyMDB9.eSsjQ4oUwG91R5zirFWxe-mkojQC01uKdvdV23zz8IJHna_589fr2yRVeHcjfRFdWhB3S6ZgAT1im50cOtYhLg9oC5ZH4HhXygPjXYDcbfDR4zg6GqIUeuBH4ij9RRJpu_mzErnXbVswWruvRmCp8Mn6fVD3LJ4cL4JkdtyLAYxofjHQBsuqPnWm7NRqscdzTXNu20-QIyl13qWn2q_rD8n70VtgDutluhcVoMWPSv6uk7wTZcpw5WXasuW79eGSZsq4dpE3Wec9yEv5sa5sNZPLnPZme_h6PfFPKmUkJKj1a9kzD4fZ3hJ809lfHTzLAgKtYNpAkEDOC1Rlpjl3h899tiChzckO21C68j36uY1Z4WWXqYpKk7Y1iq5gATG7kdIs_u8bTOKkWlt3IJVwZXaOYXhGLmrbF8u-q6-h_PGBjDql1ciAu_5Eob_Zle219NdU-WqezyR-_MSJhqv1uCjVEKfZOoa5HZtZ4vptmwVqeAZcnP7-jbPFjM3HkFBuGdysHXa-nQ-XthIXaW-AI994HcPF-Ce-8mgESJa4OcsG-sTSPNTxrheRAzrLf77e47ZKCZythqCRwqtTWI-jL-VNQpJgL2Rxn8olG6xEM3gT46MFSq9o4hX-2qgqR8KXJ0GMWCPT_WSVY3Wab-lMXpWeCZkQmfEfeijsj8g0fLg"


@pytest.mark.asyncio
async def test_verify_token_exp(jwt_service, jwt_client):
    with freeze_time("2023-03-25 12:00:00"):
        response = await jwt_client.get_token({"data": "whatever"})

    with freeze_time("2023-03-25 12:30:00"):
        data = await jwt_client.verify_token(response)

    assert data == {"data": "whatever", "exp": 1679749200}

    with freeze_time("2023-03-25 13:00:01"):
        data = await jwt_client.verify_token(response)
    assert data == {'err': 'Token expired.'}


@pytest.mark.asyncio
async def test_verify_token_malformed(jwt_service, jwt_client):
    data = await jwt_client.verify_token("ABC")
    assert data == {'err': 'Invalid token.'}
