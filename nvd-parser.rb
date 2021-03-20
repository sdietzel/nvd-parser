#!/usr/bin/env ruby

require 'json'
require 'date'
require 'mail'

MAIL = ENV['NVD_MAIL_TO']
DB_FILE = "#{__dir__}/nvd-db.json".freeze
CONFIG_FILE = "#{__dir__}/nvd-config.json".freeze

File.exist?(CONFIG_FILE) || exit(1)
File.exist?(DB_FILE) || File.write(DB_FILE, [].to_json) || exit(2)

cfg = JSON.parse(File.read(CONFIG_FILE))

PRODUCTS = cfg['products'].freeze || [].freeze
MIN_SCORE = cfg['min_score'] || 7.0
VECTOR_REQUIRED = cfg['vector_required'].freeze || [].freeze

def cpe_match?(cpe_match, search)
  cpe_match.map do |m|
    m['vulnerable'] && m['cpe23Uri'].include?(search)
  end
end

def node_match?(node, search)
  matches = []

  matches += node['children'].map { |c| node_match? c, search } if node.key? 'children'
  matches += cpe_match? node['cpe_match'], search if node.key? 'cpe_match'

  result = if node['operator'] == 'OR'
             matches.reduce(:|)
           else
             matches.reduce(:&)
           end

  result = !result if node.key?('negate') && node['negate'] == true

  result
end

def cve_match?(cve, search)
  cve['configurations']['nodes'].map { |n| node_match? n, search }.reduce(:|)
end

def severe?(cve_extract)
  vector = cve_extract[:vector]

  # Split attack vector and drop prefix, then match all required
  match = VECTOR_REQUIRED.map { |v| vector.include? v }.reduce(:&)

  match && cve_extract[:score] >= MIN_SCORE
end

def extract(cve)
  {
    id: cve['cve']['CVE_data_meta']['ID'],
    score: cve['impact']['baseMetricV3']['cvssV3']['baseScore'],
    severity: cve['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
    vector: cve['impact']['baseMetricV3']['cvssV3']['vectorString'].split('/').drop(1),
    desc: cve['cve']['description']['description_data'].map do |d|
      "#{d['value']} (#{d['lang']})"
    end,
    urls: cve['cve']['references']['reference_data'].map do |d|
      d['url']
    end,
    date: DateTime.parse(cve['publishedDate']),
    matches: PRODUCTS.filter { |p| cve_match? cve, p }
  }
end

def format_product(p)
  p.gsub(':', ' ').gsub('_', ' ').strip.upcase
end

def format(cve_extract)
  s = []

  s.append ('-' * 78)
  s.append [
    cve_extract[:id],
    cve_extract[:date].strftime('%Y-%m-%d'),
    cve_extract[:severity],
    cve_extract[:score],
    cve_extract[:vector].join('/')
  ].join(' | ')

  s.append cve_extract[:matches].map { |p| format_product p }.join(', ')
  s.append('-' * 78)

  s += cve_extract[:desc].map do |d|
    wrap = d.scan(/\S.{0,78}\S(?=\s|$)|\S+/)
    wrap.join("\n")
  end

  s.append ''

  s += cve_extract[:urls]

  s.join("\n")
end

File.write(DB_FILE, [].to_json) unless File.exist? DB_FILE

file = JSON.parse(ARGF.read)

notify_old = JSON.parse(File.read(DB_FILE))

cve_items = file['CVE_Items']

# Filter by defined products
filtered = cve_items.filter { |c| PRODUCTS.map { |p| cve_match? c, p }.reduce(:|) }

# Filter Info relevant for Mail
filtered.map! { |c| extract(c) }

# Filter by severity properties
filtered.filter! { |c| severe?(c) }

# Filter CVEs that have already been mailed
filtered.reject! { |c| notify_old.include?(c[:id]) }

notify_new = filtered.map { |f| f[:id] }

unless filtered.empty?
  mail = Mail.new

  mail.from = 'noreply@tisch20.de'
  mail.to = MAIL
  mail.subject = "[CVE] Relevant security advisories #{DateTime.now.strftime('%Y-%m-%d')}"
  mail.body = "This is a summary of all new CVE advisories relevant to the " \
              "infrastructure, with a base score of at least #{MIN_SCORE} " \
              "and an attack vector containing #{VECTOR_REQUIRED.join('/')} \n\n\n" +
              filtered.map{ |f| format f }.join("\n\n") +
              "\n\n\nInfrastructure matches used:\n\n" +
              PRODUCTS.map { |p| "- #{p}" }.join("\n")

  if MAIL
    mail.delivery_method :sendmail
    mail.deliver
  else
    puts mail.body
  end
end

# Only keep current year's numbers in cache
filter_cves = (notify_old + notify_new).filter { |i| i.include? DateTime.now.strftime('-%Y-') }

File.write(DB_FILE, filter_cves.to_json)
