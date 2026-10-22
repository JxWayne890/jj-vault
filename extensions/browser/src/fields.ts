import type { BrowserItem } from './types.ts';

export interface FieldDescriptor { autocomplete: string; type: string; name: string; id: string; label: string }
const key = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

const aliases: Record<string, string[]> = {
  'cc-name': ['cardholder', 'cardholdername', 'nameoncard', 'ccname'],
  'cc-number': ['cardnumber', 'creditcardnumber', 'ccnumber', 'number'],
  'cc-exp': ['expiry', 'expirydate', 'expiration', 'expirationdate', 'ccexp'],
  'cc-exp-month': ['expmonth', 'expirationmonth', 'month'],
  'cc-exp-year': ['expyear', 'expirationyear', 'year'],
  'cc-csc': ['cvv', 'cvc', 'securitycode', 'cccsc'],
  'name': ['fullname', 'name'],
  'given-name': ['firstname', 'givenname'],
  'family-name': ['lastname', 'surname', 'familyname'],
  'additional-name': ['middlename', 'additionalname'],
  'email': ['email', 'emailaddress'],
  'tel': ['phone', 'telephone', 'mobile', 'phonenumber'],
  'organization': ['company', 'organization', 'companyname'],
  'street-address': ['address', 'streetaddress', 'street'],
  'address-line1': ['addressline1', 'address1', 'streetaddress', 'street'],
  'address-line2': ['addressline2', 'address2', 'apartment', 'suite'],
  'address-level2': ['city', 'town', 'addresslevel2'],
  'address-level1': ['state', 'province', 'region', 'addresslevel1'],
  'postal-code': ['zip', 'zipcode', 'postalcode', 'postcode'],
  'country': ['country', 'countrycode'],
};

function customValue(item: BrowserItem, token: string): string | undefined {
  const keys = [key(token), ...(aliases[token] ?? [])];
  return item.fields?.find(field => keys.includes(key(field.label)))?.value;
}

export function fieldValue(item: BrowserItem, descriptor: FieldDescriptor): string | undefined {
  const tokens = descriptor.autocomplete.toLowerCase().split(/\s+/);
  if (tokens.includes('off')) return undefined;
  const autocomplete = tokens.find(token => token === 'one-time-code' || token === 'username' || token.includes('password') || token in aliases);
  const names = [descriptor.name, descriptor.id, descriptor.label].map(key);
  const isLogin = item.type === 'login' || item.type === 'password';
  if (isLogin) {
    if (autocomplete === 'new-password') return undefined;
    if (autocomplete === 'one-time-code' || names.some(name => /^(otp|totp|onetimecode|verificationcode|authenticatorcode)$/.test(name))) return item.totp;
    if (descriptor.type === 'password' || autocomplete === 'current-password') return item.password;
    if (autocomplete === 'username' || autocomplete === 'email' || descriptor.type === 'email' || names.some(name => /^(username|user|login|email|emailaddress|loginname)$/.test(name))) return item.username;
    return undefined;
  }
  if (descriptor.type === 'password' || autocomplete?.includes('password') || autocomplete === 'one-time-code') return undefined;
  const isCard = item.type === 'creditCard';
  if (!isCard && item.type !== 'identity') return undefined;
  let token = autocomplete;
  if (!token) token = Object.keys(aliases).find(candidate => candidate.startsWith('cc-') === isCard && names.some(name => aliases[candidate].includes(name)));
  if (!token || token.startsWith('cc-') !== isCard) return undefined;
  if (isCard && (token === 'cc-exp-month' || token === 'cc-exp-year')) {
    const direct = customValue(item, token);
    if (direct) return direct;
    const expiry = customValue(item, 'cc-exp');
    const match = expiry?.match(/^(\d{1,2})\s*\/\s*(\d{2}|\d{4})$/);
    if (match) return token === 'cc-exp-month' ? match[1].padStart(2, '0') : match[2].length === 2 ? `20${match[2]}` : match[2];
  }
  return customValue(item, token);
}
