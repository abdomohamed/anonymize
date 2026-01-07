#!/usr/bin/env python3
"""Generate 1000 randomized test CSV rows similar to the sample."""

import csv
import random
from datetime import datetime, timedelta
from faker import Faker

fake = Faker('en_AU')

# Australian state codes and suburbs
STATES = ['VIC', 'NSW', 'QLD', 'SA', 'WA', 'TAS', 'NT', 'ACT']
SUBURBS = {
    'VIC': ['Golden Square', 'Richmond', 'Fitzroy', 'Carlton', 'Brunswick', 'Collingwood', 'South Yarra', 'Prahran', 'St Kilda', 'Footscray'],
    'NSW': ['Surry Hills', 'Newtown', 'Bondi', 'Manly', 'Parramatta', 'Chatswood', 'Penrith', 'Blacktown', 'Liverpool', 'Bankstown'],
    'QLD': ['Fortitude Valley', 'South Brisbane', 'Toowong', 'Woolloongabba', 'Kangaroo Point', 'New Farm', 'West End', 'Milton', 'Paddington', 'Bulimba'],
    'SA': ['Adelaide', 'Glenelg', 'Norwood', 'Unley', 'Prospect', 'Port Adelaide', 'Marion', 'Salisbury', 'Elizabeth', 'Tea Tree Gully'],
    'WA': ['Fremantle', 'Subiaco', 'Cottesloe', 'Scarborough', 'Joondalup', 'Rockingham', 'Mandurah', 'Armadale', 'Midland', 'Cannington'],
    'TAS': ['Hobart', 'Launceston', 'Devonport', 'Burnie', 'Kingston', 'Sandy Bay', 'Glenorchy', 'New Town', 'Moonah', 'Rosny'],
    'NT': ['Darwin', 'Alice Springs', 'Katherine', 'Palmerston', 'Casuarina', 'Nightcliff', 'Stuart Park', 'Fannie Bay', 'Parap', 'Rapid Creek'],
    'ACT': ['Canberra', 'Belconnen', 'Woden', 'Tuggeranong', 'Gungahlin', 'Fyshwick', 'Kingston', 'Braddon', 'Dickson', 'Civic']
}

# Street types
STREET_TYPES = ['St', 'Rd', 'Ave', 'Cr', 'Dr', 'Pl', 'Ct', 'Way', 'Ln', 'Blvd', 'Tce', 'Pde']

# Systems and reference types
SYSTEMS = ['Telstra', 'Optus', 'NBN Co', 'Vodafone', 'TPG', 'iiNet', 'Aussie Broadband', 'Belong', 'Dodo', 'Internode']
REF_PREFIXES = ['CRM', 'TKT', 'INC', 'SR', 'REQ', 'CHG', 'PRB', 'CASE', 'REF', 'ORD']

# Agent ID formats
AGENT_FORMATS = [
    lambda: f"D{random.randint(100000, 999999)}",
    lambda: f"A{random.randint(10000, 99999)}",
    lambda: f"EMP{random.randint(1000, 9999)}",
    lambda: f"{random.choice(['SYD', 'MEL', 'BRI', 'PER', 'ADL'])}{random.randint(100, 999)}",
    lambda: f"agent_{fake.user_name()}",
    lambda: f"{fake.first_name().lower()}.{fake.last_name().lower()}",
]

# Phone number formats
def random_phone():
    formats = [
        lambda: f"04{random.randint(10000000, 99999999)}",
        lambda: f"04{random.randint(10, 99)} {random.randint(100, 999)} {random.randint(100, 999)}",
        lambda: f"04{random.randint(10, 99)}-{random.randint(100, 999)}-{random.randint(100, 999)}",
        lambda: f"+614{random.randint(10000000, 99999999)}",
        lambda: f"+61 4{random.randint(10, 99)} {random.randint(100, 999)} {random.randint(100, 999)}",
        lambda: f"0{random.randint(2, 9)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}",
        lambda: f"(0{random.randint(2, 9)}) {random.randint(1000, 9999)} {random.randint(1000, 9999)}",
    ]
    return random.choice(formats)()

# Medicare formats
def random_medicare():
    base = random.randint(2000000000, 6999999999)
    formats = [
        lambda: str(base),
        lambda: f"{str(base)[:4]} {str(base)[4:9]} {str(base)[9]}",
        lambda: f"{str(base)[:4]}-{str(base)[4:9]}-{str(base)[9]}",
    ]
    return random.choice(formats)()

# Driver license formats by state
def random_license(state):
    formats = {
        'VIC': lambda: f"{random.randint(100000000, 999999999)}",
        'NSW': lambda: f"{random.choice(['AB', 'CD', 'EF', 'GH'])}{random.randint(100000, 999999)}",
        'QLD': lambda: f"{random.randint(10000000, 99999999)}",
        'SA': lambda: f"{random.choice(['S', 'SA'])}{random.randint(10000, 99999)}",
        'WA': lambda: f"{random.randint(1000000, 9999999)}",
        'TAS': lambda: f"{random.randint(100000, 999999)}",
        'NT': lambda: f"{random.randint(100000, 999999)}",
        'ACT': lambda: f"{random.randint(1000000, 9999999)}",
    }
    return formats.get(state, formats['VIC'])()

# NBN reference formats
def random_nbn():
    loc = f"LOC{random.randint(100000000000, 999999999999)}"
    avc = f"AVC{random.randint(100000000000, 999999999999)}"
    return loc, avc

# Date formats
def random_date():
    d = fake.date_between(start_date='-5y', end_date='+1y')
    formats = [
        lambda: d.strftime("%d/%m/%Y"),
        lambda: d.strftime("%d-%m-%Y"),
        lambda: d.strftime("%Y-%m-%d"),
        lambda: d.strftime("%B %d, %Y"),
        lambda: d.strftime("%d %B %Y"),
        lambda: d.strftime("%d %b %Y"),
    ]
    return random.choice(formats)()

# DOB formats
def random_dob():
    d = fake.date_of_birth(minimum_age=18, maximum_age=85)
    formats = [
        lambda: d.strftime("%d/%m/%Y"),
        lambda: d.strftime("%d-%m-%Y"),
        lambda: d.strftime("%d %B %Y"),
        lambda: d.strftime("%d/%m/%y"),
        lambda: f"DOB: {d.strftime('%d/%m/%Y')}",
        lambda: f"Date of Birth: {d.strftime('%d %B %Y')}",
        lambda: f"Born: {d.strftime('%d/%m/%Y')}",
    ]
    return random.choice(formats)()

# Account/Case number formats
def random_account():
    formats = [
        lambda: str(random.randint(100000000, 999999999)),
        lambda: f"ACC{random.randint(10000000, 99999999)}",
        lambda: f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}",
        lambda: f"CUS{random.randint(100000, 999999)}",
    ]
    return random.choice(formats)()

def random_case():
    formats = [
        lambda: str(random.randint(1000000, 9999999)),
        lambda: f"#{random.randint(10000, 99999)}",
        lambda: f"Case #{random.randint(10000, 99999)}",
        lambda: f"CASE-{random.randint(100000, 999999)}",
    ]
    return random.choice(formats)()

# Email formats
def random_email(first_name, last_name):
    domains = ['email.com', 'gmail.com', 'outlook.com', 'yahoo.com.au', 'hotmail.com', 'bigpond.com', 'icloud.com', 'live.com.au']
    formats = [
        lambda: f"{first_name.lower()}.{last_name.lower()}@{random.choice(domains)}",
        lambda: f"{first_name.lower()}{last_name.lower()}@{random.choice(domains)}",
        lambda: f"{first_name[0].lower()}{last_name.lower()}@{random.choice(domains)}",
        lambda: f"{first_name.lower()}_{last_name.lower()}@{random.choice(domains)}",
        lambda: f"{last_name.lower()}.{first_name.lower()}@{random.choice(domains)}",
        lambda: f"{first_name.lower()}{random.randint(1, 99)}@{random.choice(domains)}",
    ]
    return random.choice(formats)()

# Address formats
def random_address(state):
    suburb = random.choice(SUBURBS[state])
    postcode = random.randint(2000, 7999)
    street_num = random.randint(1, 500)
    street_name = fake.street_name().split()[0]
    street_type = random.choice(STREET_TYPES)

    formats = [
        lambda: f"{street_num} {street_name} {street_type}, {suburb} {state} {postcode}",
        lambda: f"{street_num} {street_name} {street_type} {suburb} {state} {postcode}",
        lambda: f"Unit {random.randint(1, 50)}/{street_num} {street_name} {street_type}, {suburb} {state} {postcode}",
        lambda: f"{street_num}/{random.randint(1, 200)} {street_name} {street_type}, {suburb} {state}",
        lambda: f"{street_num} {street_name} {street_type}, {suburb} {state} {postcode}",
    ]
    return random.choice(formats)()

# TFN format
def random_tfn():
    tfn = str(random.randint(100000000, 999999999))
    formats = [
        lambda: tfn,
        lambda: f"{tfn[:3]} {tfn[3:6]} {tfn[6:]}",
        lambda: f"{tfn[:3]}-{tfn[3:6]}-{tfn[6:]}",
    ]
    return random.choice(formats)()

# ABN format
def random_abn():
    abn = str(random.randint(10000000000, 99999999999))
    formats = [
        lambda: abn,
        lambda: f"{abn[:2]} {abn[2:5]} {abn[5:8]} {abn[8:]}",
        lambda: f"ABN: {abn[:2]} {abn[2:5]} {abn[5:8]} {abn[8:]}",
    ]
    return random.choice(formats)()

# Credit card (fake/masked)
def random_cc():
    formats = [
        lambda: f"**** **** **** {random.randint(1000, 9999)}",
        lambda: f"XXXX-XXXX-XXXX-{random.randint(1000, 9999)}",
        lambda: f"Card ending {random.randint(1000, 9999)}",
        lambda: f"4{random.randint(100, 999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}",
    ]
    return random.choice(formats)()

# Centrelink CRN
def random_crn():
    letters = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=3))
    numbers = ''.join(random.choices('0123456789', k=6))
    return f"{numbers}{letters}"

# Generate comment templates
def generate_comment():
    state = random.choice(STATES)
    first_name = fake.first_name()
    last_name = fake.last_name()
    first_name2 = fake.first_name()
    last_name2 = fake.last_name()

    templates = [
        # Template 1: Full customer interaction (like the sample)
        lambda: f"Customer Name: {first_name.upper()} {last_name.upper()} Contact number: {random_phone()} Case {random_case()} Account: {random_account()} Agent: {random.choice(AGENT_FORMATS)()} spoke with {first_name2} {last_name2} ({random_dob()}) at {random_address(state)}. Medicare {random_medicare()}, license {state.lower()} {random_license(state)}. Email: {random_email(first_name2, last_name2)} Ph: {random_phone()} NBN: {random_nbn()[0]} {random_nbn()[1]} Next Contact: {random_date()} {random.choice(SYSTEMS)} ref: {random.choice(REF_PREFIXES)}-{random.randint(2020, 2026)}-{random.randint(100, 999)}",

        # Template 2: Short call note
        lambda: f"Called {first_name} {last_name} on {random_phone()} re: account {random_account()}. Customer confirmed DOB {random_dob()} and address {random_address(state)}. Issue resolved. Ref: {random.choice(REF_PREFIXES)}{random.randint(10000, 99999)}",

        # Template 3: Email interaction
        lambda: f"Email from {random_email(first_name, last_name)} - Customer {first_name} {last_name} requesting service change. Verified identity: Medicare {random_medicare()}, Phone {random_phone()}. {random.choice(SYSTEMS)} ticket {random.choice(REF_PREFIXES)}-{random.randint(100000, 999999)} created.",

        # Template 4: Technical support
        lambda: f"Tech support case for {first_name} {last_name}. NBN Location ID: {random_nbn()[0]}, AVC: {random_nbn()[1]}. Customer at {random_address(state)}. Contact: {random_phone()} / {random_email(first_name, last_name)}. Agent {random.choice(AGENT_FORMATS)()} escalated to {random.choice(SYSTEMS)}.",

        # Template 5: Account verification
        lambda: f"Account verification: {first_name.upper()} {last_name.upper()} | DOB: {random_dob()} | Address: {random_address(state)} | Phone: {random_phone()} | Email: {random_email(first_name, last_name)} | License: {state} {random_license(state)} | Medicare: {random_medicare()} | Account: {random_account()} | Verified by: {random.choice(AGENT_FORMATS)()}",

        # Template 6: Complaint handling
        lambda: f"Complaint from {first_name} {last_name} ({random_phone()}) regarding billing issue. Account {random_account()}, {random.choice(SYSTEMS)} customer since {random_date()}. Credited ${random.randint(10, 500)}.{random.randint(0, 99):02d}. Case {random_case()} - {random.choice(AGENT_FORMATS)()}",

        # Template 7: New connection
        lambda: f"New connection request - {first_name} {last_name} | Install Address: {random_address(state)} | Contact: {random_phone()} | Email: {random_email(first_name, last_name)} | ID Verified: DL {state} {random_license(state)} | Scheduled: {random_date()} | {random.choice(SYSTEMS)} Order: {random.choice(REF_PREFIXES)}{random.randint(1000000, 9999999)}",

        # Template 8: Business account
        lambda: f"Business account - {fake.company()} | ABN: {random_abn()} | Contact: {first_name} {last_name} ({random_phone()}) | Email: {random_email(first_name, last_name)} | Address: {random_address(state)} | Account: {random_account()} | Payment: Card {random_cc()}",

        # Template 9: Service cancellation
        lambda: f"Cancellation request from {first_name} {last_name}. Account {random_account()} to be closed {random_date()}. Final bill to {random_address(state)}. Contact {random_phone()} if issues. Processed by {random.choice(AGENT_FORMATS)()} - {random.choice(SYSTEMS)} {random.choice(REF_PREFIXES)}{random.randint(10000, 99999)}",

        # Template 10: Fault report
        lambda: f"Fault logged by {first_name} {last_name} at {random_address(state)}. No service since {random_date()}. NBN {random_nbn()[0]}. Callback: {random_phone()}. Medicare for ID: {random_medicare()}. Tech visit scheduled. {random.choice(SYSTEMS)} incident {random.choice(REF_PREFIXES)}-{random.randint(100000, 999999)}",

        # Template 11: Payment received
        lambda: f"Payment ${random.randint(50, 500)}.{random.randint(0, 99):02d} received from {first_name} {last_name} ({random_account()}). Card ending {random.randint(1000, 9999)}. Receipt sent to {random_email(first_name, last_name)}. Agent: {random.choice(AGENT_FORMATS)()}",

        # Template 12: Address change
        lambda: f"Address update for {first_name.upper()} {last_name.upper()} (DOB {random_dob()}) | Old: {random_address(random.choice(STATES))} | New: {random_address(state)} | Phone: {random_phone()} | Confirmed via license {state} {random_license(state)} | {random.choice(REF_PREFIXES)}{random.randint(10000, 99999)}",

        # Template 13: Callback note
        lambda: f"CB to {first_name} {last_name} at {random_phone()} re case {random_case()}. Left VM. Alt contact: {random_phone()}. Email: {random_email(first_name, last_name)}. Address on file: {random_address(state)}. Follow up {random_date()}. - {random.choice(AGENT_FORMATS)()}",

        # Template 14: ID verification failed
        lambda: f"ID verification FAILED for caller claiming to be {first_name} {last_name}. Could not verify DOB or Medicare {random_medicare()}. Account {random_account()} flagged. Phone used: {random_phone()}. Security team notified. {random.choice(REF_PREFIXES)}{random.randint(100000, 999999)}",

        # Template 15: Multi-service note
        lambda: f"{first_name} {last_name} - {random.choice(SYSTEMS)} customer | Services: NBN ({random_nbn()[0]}), Mobile ({random_phone()}) | Account: {random_account()} | Address: {random_address(state)} | DOB: {random_dob()} | Email: {random_email(first_name, last_name)} | Last contact: {random_date()} | Agent: {random.choice(AGENT_FORMATS)()}",

        # Template 16: Centrelink/Government
        lambda: f"Customer {first_name} {last_name} provided Centrelink CRN {random_crn()} for concession verification. DOB: {random_dob()}, Medicare: {random_medicare()}. Address: {random_address(state)}. Phone: {random_phone()}. Discount applied to account {random_account()}.",

        # Template 17: Emergency contact update
        lambda: f"Emergency contact updated for {first_name} {last_name} (Acc: {random_account()}) | Primary: {first_name2} {last_name2} - {random_phone()} | Relationship: {random.choice(['Spouse', 'Parent', 'Child', 'Sibling', 'Partner'])} | Customer email: {random_email(first_name, last_name)} | Updated by: {random.choice(AGENT_FORMATS)()}",

        # Template 18: International format
        lambda: f"International customer {first_name} {last_name} | Passport: {fake.passport_number()} | AU Contact: {random_phone()} | OS Contact: +{random.randint(1, 99)} {random.randint(100, 999)} {random.randint(1000000, 9999999)} | Email: {random_email(first_name, last_name)} | Temp address: {random_address(state)} | {random.choice(SYSTEMS)} roaming case {random.choice(REF_PREFIXES)}{random.randint(10000, 99999)}",

        # Template 19: Credit check
        lambda: f"Credit check completed for {first_name.upper()} {last_name.upper()} | DOB: {random_dob()} | License: {state} {random_license(state)} | Address: {random_address(state)} | Employer: {fake.company()} | Phone: {random_phone()} | Result: {random.choice(['APPROVED', 'APPROVED', 'APPROVED', 'REFER', 'DECLINED'])} | Ref: {random.choice(REF_PREFIXES)}{random.randint(100000, 999999)}",

        # Template 20: Equipment return
        lambda: f"Equipment return from {first_name} {last_name} | Account: {random_account()} | Return address: {random_address(state)} | Contact: {random_phone()} | Items: {random.choice(['Modem', 'Router', 'Set-top box', 'Mobile device'])} S/N: {fake.uuid4()[:8].upper()} | Refund to card ****{random.randint(1000, 9999)} | Tracking: {random.choice(REF_PREFIXES)}{random.randint(1000000000, 9999999999)}",
    ]

    return random.choice(templates)()

def main():
    rows = []
    start_date = datetime(2019, 1, 1)

    for i in range(1000):
        case_number = random.randint(1000000, 9999999)
        created_date = start_date + timedelta(days=random.randint(0, 2000))
        comment = generate_comment()

        rows.append({
            'CaseNumber': case_number,
            'CreatedDate': created_date.strftime('%Y-%m-%d'),
            'CommentBody': comment
        })

    # Write to CSV
    output_file = '/workspaces/anonymize/test_1000.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['CaseNumber', 'CreatedDate', 'CommentBody'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"✓ Generated {len(rows)} rows to {output_file}")

    # Show a few samples
    print("\nSample rows:")
    for i in [0, 250, 500, 750, 999]:
        print(f"\n--- Row {i+1} ---")
        print(f"CaseNumber: {rows[i]['CaseNumber']}")
        print(f"CreatedDate: {rows[i]['CreatedDate']}")
        print(f"CommentBody: {rows[i]['CommentBody'][:200]}...")

if __name__ == '__main__':
    main()
